import argparse
import json
import os
import sys
import re
import socket
import struct
import subprocess
import threading
import time

START = time.time()
VERBOSE = False
JSON_OUT = False


def _positive_float(s):
    try:
        v = float(s)
    except ValueError:
        raise argparse.ArgumentTypeError("bad timeout value: %s" % s)
    if v <= 0:
        raise argparse.ArgumentTypeError("timeout must be positive")
    return v


def _parse_argv(argv):
    p = argparse.ArgumentParser(
        prog="syspkt",
        description="Correlate sendto() syscalls with TCP packets on the wire.",
    )
    p.add_argument(
        "host", nargs="?", default="127.0.0.1",
        help="host to connect to (default: 127.0.0.1)",
    )
    p.add_argument(
        "port", nargs="?", type=int, default=9999,
        help="port to connect to (default: 9999)",
    )
    p.add_argument(
        "msg", nargs="?", default="hello",
        help="message to send (default: hello)",
    )
    p.add_argument(
        "--iface", default="lo",
        help="interface to capture on, or 'any' (default: lo)",
    )
    p.add_argument(
        "--timeout", type=_positive_float, default=None,
        help="max seconds to trace",
    )
    p.add_argument(
        "--json", action="store_true",
        help="output JSONL",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="verbose progress",
    )
    return p.parse_args(argv)


def _log(msg):
    if VERBOSE and not JSON_OUT:
        sys.stderr.write("[%7.3f] %s\n" % (time.time() - START, msg))
        sys.stderr.flush()


def _emit(obj):
    if JSON_OUT:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()


def _validate_iface(iface):
    if not iface or iface in ("any", "*"):
        return
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    except PermissionError:
        sys.stderr.write("need root or CAP_NET_RAW\n")
        sys.exit(1)
    try:
        sock.bind((iface, 0))
    except OSError as e:
        sys.stderr.write("cannot use interface %r: %s\n" % (iface, e))
        try:
            names = sorted(os.listdir("/sys/class/net"))
            sys.stderr.write("available interfaces: %s\n" % ", ".join(names))
        except OSError:
            pass
        sys.exit(1)
    finally:
        sock.close()


def _kill_proc(proc):
    if proc is None:
        return
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=2)
    except (subprocess.TimeoutExpired, OSError):
        pass


def _cleanup(*, st, srv, sn, cap_thread, stop_capture, log):
    _log("entering finally")
    stop_capture.set()
    if cap_thread is not None:
        cap_thread.join(timeout=2)
    _kill_proc(st)
    _kill_proc(srv)
    if sn is not None:
        try:
            sn.close()
        except OSError:
            pass
    try:
        if os.path.exists(log):
            os.remove(log)
    except OSError:
        pass
    _log("cleanup done")


def _pkill_old_servers():
    _log("pkill old servers")
    try:
        subprocess.run(
            [
                "pkill", "-f",
                "s\\.setsockopt\\(socket\\.SOL_SOCKET, "
                "socket\\.SO_REUSEADDR, 1\\)",
            ],
            capture_output=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        _log("pkill skipped: %s" % e)


def _remove_log_file(log):
    _log("removing old log")
    try:
        if os.path.exists(log):
            os.remove(log)
    except OSError as e:
        _log("remove failed: %s" % e)


def _spawn_server(srv_code):
    _log("spawning server")
    srv = subprocess.Popen(
        ["python3", "-c", srv_code],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _log("server pid=%d" % srv.pid)
    time.sleep(.5)
    _log("server warm-up done, poll=%r" % srv.poll())
    return srv


def _open_raw_socket(iface):
    _log("binding raw socket on %s" % iface)
    sn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    if iface and iface not in ("any", "*"):
        sn.bind((iface, 0))
    sn.settimeout(.1)
    try:
        sn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 * 1024 * 1024)
        _log("SO_RCVBUF set to 32MB")
    except OSError as e:
        _log("SO_RCVBUF failed: %s" % e)
    return sn


def _start_capture(sn, port, pkts, stats, stop_capture):
    cap_thread = threading.Thread(
        target=_capture,
        args=(sn, port, pkts, stats, stop_capture),
        daemon=True,
    )
    cap_thread.start()
    _log("capture thread started")
    return cap_thread


def _stop_capture(cap_thread, stop_capture, sn, pkts, port, stats):
    _log("stopping capture thread")
    stop_capture.set()
    if cap_thread is not None:
        cap_thread.join(timeout=2)
    if sn is not None:
        try:
            sn.close()
        except OSError:
            pass
    _log("captured %d packets on port %d (raw reads: %d)" % (len(pkts), port, stats["reads"]))


def _spawn_strace(log, cli_code):
    _log("spawning strace")
    st = subprocess.Popen(
        [
            "strace", "-f", "-y", "-e", "trace=%network",
            "-o", log, "python3", "-c", cli_code,
        ],
    )
    st_start = time.time()
    _log("strace pid=%d" % st.pid)
    return st, st_start


def _wait_strace(st, st_start, timeout):
    _log("waiting for strace (timeout=%r)" % timeout)
    while True:
        try:
            st.wait(timeout=0.5)
            _log("strace finished rc=%d after %.2fs" % (st.returncode, time.time() - st_start))
            return False
        except subprocess.TimeoutExpired:
            elapsed = time.time() - st_start
            _log("strace still running, t=%.1fs" % elapsed)
            if timeout is not None and elapsed > timeout:
                _log("timeout exceeded, killing strace")
                _kill_proc(st)
                return True


def _build_srv_code(host, port):
    return (
        "import socket; "
        "s=socket.socket(); "
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
        "s.bind((\"%s\", %d)); "
        "s.listen(1); "
        "c,_=s.accept(); "
        "c.recv(1024); "
        "c.close()"
    ) % (host, port)


def _build_cli_code(host, port, msg_hex):
    return (
        "import socket, struct, sys, time; "
        "s=socket.create_connection((\"%s\", %d)); "
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack(\"ii\", 1, 0)); "
        "time.sleep(1); "
        "s.send(bytes.fromhex(\"%s\")); "
        "s.close()"
    ) % (host, port, msg_hex)


def _parse_packet(data):
    if len(data) < 54:
        return None
    if data[12:14] != b"\x08\x00":
        return None
    if data[23] != 6:
        return None
    ihl = (data[14] & 0x0F) * 4
    tcp_off = 14 + ihl
    if len(data) < tcp_off + 20:
        return None
    sp, dp, sq = struct.unpack("!HHI", data[tcp_off:tcp_off + 8])
    doff = (data[tcp_off + 12] >> 4) * 4
    off = tcp_off + doff
    fl = data[tcp_off + 13]
    pl = len(data) - off
    if pl < 0:
        return None
    return sp, dp, sq, pl, off, fl


def _parse_captured(pkts, port):
    seen = set()
    parsed = []
    for data in pkts:
        info = _parse_packet(data)
        if info is None:
            continue
        sp, dp, sq, pl, off, fl = info
        if port not in (sp, dp):
            continue
        k = (sp, dp, sq, pl)
        if k in seen:
            continue
        seen.add(k)
        parsed.append((sp, dp, sq, pl, off, fl, data))
    return parsed


def _parse_strace_log(path):
    sends = []
    try:
        f = open(path)
    except FileNotFoundError:
        return sends
    with f:
        for line in f:
            m = re.search(r"socket:\[(\d+)\]", line)
            n = re.search(r"=\s*(\d+)\s*$", line)
            if m and n and "send" in line:
                sends.append((m.group(1), int(n.group(1))))
    return sends


def _poll_proc_net_tcp(duration=1.5, timeout_at=None):
    conns = {}
    start = time.time()
    i = 0
    while time.time() - start < duration:
        try:
            with open("/proc/net/tcp") as f:
                for r in f.read().split("\n")[1:]:
                    p = r.split()
                    if len(p) > 9:
                        conns[p[9]] = (p[1], p[2])
        except (FileNotFoundError, OSError):
            pass
        if i % 10 == 0:
            _log("  poll %d, %d conns" % (i, len(conns)))
        if timeout_at is not None and time.time() > timeout_at:
            return conns, True
        time.sleep(.05)
        i += 1
    return conns, False


def _capture(sock, port, out, stats, stop):
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        stats["reads"] += 1
        info = _parse_packet(data)
        if info is None:
            continue
        sp, dp = info[0], info[1]
        if port not in (sp, dp):
            continue
        out.append(data)
        stats["matched"] += 1


def _flags(fl):
    fs = []
    if fl & 0x02:
        fs.append("SYN")
    if fl & 0x01:
        fs.append("FIN")
    if fl & 0x04:
        fs.append("RST")
    if fl & 0x08:
        fs.append("PSH")
    if fl & 0x10:
        fs.append("ACK")
    if fl & 0x20:
        fs.append("URG")
    return fs


def _h2ip(hex_ip, hex_port):
    return "%d.%d.%d.%d:%d" % (
        int(hex_ip[6:8], 16), int(hex_ip[4:6], 16),
        int(hex_ip[2:4], 16), int(hex_ip[0:2], 16),
        int(hex_port, 16),
    )


def _parse_conn(conns, ino):
    if ino not in conns:
        return None
    lh, lp = conns[ino][0].split(":")
    rh, rp = conns[ino][1].split(":")
    return (
        _h2ip(lh, lp), _h2ip(rh, rp),
        int(lp, 16), int(rp, 16),
    )


def _emit_packet(sq, pl, off, fl, p, lport, rport):
    fs = _flags(fl)
    if not JSON_OUT:
        fs_s = "-".join(fs) if fs else "NONE"
        if pl == 0:
            print("  %s ->" % fs_s, lport, "->", rport, "seq", sq, flush=True)
        else:
            print(
                "  %s ->" % fs_s, lport, "->", rport,
                "seq", sq, "payload", pl, repr(p[off:off + pl]),
                flush=True,
            )
    _emit({
        "type": "packet",
        "src": "%d.%d.%d.%d:%d" % (
            int(p[26]), int(p[27]), int(p[28]), int(p[29]), lport,
        ),
        "dst": "%d.%d.%d.%d:%d" % (
            int(p[30]), int(p[31]), int(p[32]), int(p[33]), rport,
        ),
        "seq": sq,
        "flags": fs,
        "payload_len": pl,
        "payload": p[off:off + pl].decode("utf-8", "replace") if pl > 0 else "",
    })


def _match(sends, conns, parsed):
    matched = 0
    printed_inodes = set()
    for ino, nb in sends:
        if not JSON_OUT:
            print("sendto", nb, "bytes", flush=True)
        info = _parse_conn(conns, ino)
        if info is None:
            _log("inode %s not in conns, skipped" % ino)
            _emit({"type": "sendto", "bytes": nb, "matched": False})
            continue
        ls, rs, lport, rport = info
        if not JSON_OUT:
            print("  conn", ls, "->", rs, flush=True)
        _emit({"type": "conn", "src": ls, "dst": rs})
        events = []
        for sp, dp, sq, pl, off, fl, p in parsed:
            if sp == lport and dp == rport:
                events.append((sq, pl, off, fl, p))
        events.sort()
        if ino not in printed_inodes:
            printed_inodes.add(ino)
            for sq, pl, off, fl, p in events:
                _emit_packet(sq, pl, off, fl, p, lport, rport)
        hit = False
        for sq, pl, off, fl, p in events:
            if pl == nb:
                matched += 1
                hit = True
                break
        _emit({"type": "sendto", "bytes": nb, "matched": hit})
    return matched


def main(argv=None):
    global VERBOSE, JSON_OUT

    args = _parse_argv(sys.argv[1:] if argv is None else argv)
    VERBOSE = args.verbose
    JSON_OUT = args.json

    host = args.host
    port = args.port
    msg = args.msg.encode()
    iface = args.iface
    timeout = args.timeout
    log = "/tmp/t.log"

    _log("verbose on")
    _log("json=%r verbose=%r timeout=%r iface=%r" % (JSON_OUT, VERBOSE, timeout, iface))
    _log("host=%s port=%d msg=%r" % (host, port, msg))

    _validate_iface(iface)

    srv_code = _build_srv_code(host, port)
    cli_code = _build_cli_code(host, port, msg.hex())

    if not JSON_OUT:
        print("start", flush=True)

    _pkill_old_servers()
    _remove_log_file(log)

    srv = None
    st = None
    sn = None
    cap_thread = None
    stop_capture = threading.Event()
    stats = {"reads": 0, "matched": 0}
    timed_out = False

    try:
        srv = _spawn_server(srv_code)
        sn = _open_raw_socket(iface)

        pkts = []
        cap_thread = _start_capture(sn, port, pkts, stats, stop_capture)

        st, st_start = _spawn_strace(log, cli_code)

        timeout_at = (st_start + timeout) if timeout is not None else None
        conns, timed_out = _poll_proc_net_tcp(duration=1.5, timeout_at=timeout_at)
        if timed_out:
            _log("timeout during polling, killing strace")
        _log("collected %d conns" % len(conns))

        if timed_out:
            _kill_proc(st)
        else:
            timed_out = _wait_strace(st, st_start, timeout)
        st = None

        _stop_capture(cap_thread, stop_capture, sn, pkts, port, stats)
        cap_thread = None
        sn = None

        if timed_out:
            if not JSON_OUT:
                print("timeout after %.1fs" % timeout, flush=True)
            _emit({"type": "timeout", "after": timeout})
            return 124

        parsed = _parse_captured(pkts, port)
        _log("parsed %d unique packets" % len(parsed))

        sends = _parse_strace_log(log)
        _log("read %d send() calls" % len(sends))

        matched = _match(sends, conns, parsed)
        _log("matched %d sendto calls" % matched)

        if matched == 0:
            _log("no match, exit 1")
            return 1
        return 0

    except KeyboardInterrupt:
        if not JSON_OUT:
            print("\ninterrupted", flush=True)
        _emit({"type": "interrupted"})
        return 130

    except Exception as e:
        sys.stderr.write("error: %s: %s\n" % (type(e).__name__, e))
        return 1

    finally:
        _cleanup(
            st=st,
            srv=srv,
            sn=sn,
            cap_thread=cap_thread,
            stop_capture=stop_capture,
            log=log,
        )


if __name__ == "__main__":
    sys.exit(main())

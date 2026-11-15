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
TIMEOUT = None
IFACE = "lo"


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


args = _parse_argv(sys.argv[1:])

HOST = args.host
PORT = args.port
MSG = args.msg.encode()
IFACE = args.iface
TIMEOUT = args.timeout
VERBOSE = args.verbose
JSON_OUT = args.json
LOG = "/tmp/t.log"

_log("verbose on")
_log("json=%r verbose=%r timeout=%r iface=%r" % (JSON_OUT, VERBOSE, TIMEOUT, IFACE))
_log("host=%s port=%d msg=%r" % (HOST, PORT, MSG))

if IFACE and IFACE not in ("any", "*"):
    try:
        _test = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    except PermissionError:
        sys.stderr.write("need root or CAP_NET_RAW\n")
        sys.exit(1)
    try:
        _test.bind((IFACE, 0))
    except OSError as e:
        sys.stderr.write("cannot use interface %r: %s\n" % (IFACE, e))
        try:
            names = sorted(os.listdir("/sys/class/net"))
            sys.stderr.write("available interfaces: %s\n" % ", ".join(names))
        except OSError:
            pass
        sys.exit(1)
    finally:
        _test.close()

SRV_CODE = (
    "import socket; "
    "s=socket.socket(); "
    "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
    "s.bind((\"%s\", %d)); "
    "s.listen(1); "
    "c,_=s.accept(); "
    "c.recv(1024); "
    "c.close()"
) % (HOST, PORT)

CLI_CODE = (
    "import socket, struct, sys, time; "
    "s=socket.create_connection((\"%s\", %d)); "
    "s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack(\"ii\", 1, 0)); "
    "time.sleep(1); "
    "s.send(bytes.fromhex(\"%s\")); "
    "s.close()"
) % (HOST, PORT, MSG.hex())

if not JSON_OUT:
    print("start", flush=True)

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

srv = None
st = None
sn = None
cap_thread = None
stop_capture = threading.Event()
stats = {"reads": 0, "matched": 0}
timed_out = False


def _capture(sock, port, out, stats, stop):
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        stats["reads"] += 1
        if len(data) < 54:
            continue
        if data[12:14] != b"\x08\x00":
            continue
        if data[23] != 6:
            continue
        ihl = (data[14] & 0x0F) * 4
        tcp_off = 14 + ihl
        if len(data) < tcp_off + 4:
            continue
        sp, dp = struct.unpack("!HH", data[tcp_off:tcp_off + 4])
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


try:
    _log("removing old log")
    try:
        if os.path.exists(LOG):
            os.remove(LOG)
    except OSError as e:
        _log("remove failed: %s" % e)

    _log("spawning server")
    srv = subprocess.Popen(
        ["python3", "-c", SRV_CODE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _log("server pid=%d" % srv.pid)
    time.sleep(.5)
    _log("server warm-up done, poll=%r" % srv.poll())

    _log("binding raw socket on %s" % IFACE)
    sn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    if IFACE and IFACE not in ("any", "*"):
        sn.bind((IFACE, 0))
    sn.settimeout(.1)
    try:
        sn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 * 1024 * 1024)
        _log("SO_RCVBUF set to 32MB")
    except OSError as e:
        _log("SO_RCVBUF failed: %s" % e)

    pkts = []
    cap_thread = threading.Thread(
        target=_capture,
        args=(sn, PORT, pkts, stats, stop_capture),
        daemon=True,
    )
    cap_thread.start()
    _log("capture thread started")

    _log("spawning strace")
    st = subprocess.Popen(
        [
            "strace", "-f", "-y", "-e", "trace=%network",
            "-o", LOG, "python3", "-c", CLI_CODE,
        ],
    )
    st_start = time.time()
    _log("strace pid=%d" % st.pid)

    _log("polling /proc/net/tcp")
    conns = {}
    for i in range(30):
        with open("/proc/net/tcp") as f:
            for r in f.read().split("\n")[1:]:
                p = r.split()
                if len(p) > 9:
                    conns[p[9]] = (p[1], p[2])
        if i % 10 == 0:
            _log("  poll %d/30, %d conns" % (i, len(conns)))
        if TIMEOUT is not None and time.time() - st_start > TIMEOUT:
            _log("timeout during polling, killing strace")
            timed_out = True
            st.kill()
            break
        time.sleep(.05)
    _log("collected %d conns" % len(conns))

    if not timed_out:
        _log("waiting for strace (timeout=%r)" % TIMEOUT)
        while True:
            try:
                st.wait(timeout=0.5)
                _log("strace finished rc=%d after %.2fs" % (st.returncode, time.time() - st_start))
                break
            except subprocess.TimeoutExpired:
                elapsed = time.time() - st_start
                _log("strace still running, t=%.1fs" % elapsed)
                if TIMEOUT is not None and elapsed > TIMEOUT:
                    _log("timeout exceeded, killing strace")
                    timed_out = True
                    st.kill()
                    try:
                        st.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        _log("strace did not die after kill")
                    break
    st = None

    _log("stopping capture thread")
    stop_capture.set()
    cap_thread.join(timeout=2)
    cap_thread = None
    sn.close()
    sn = None
    _log("captured %d packets on port %d (raw reads: %d)" % (len(pkts), PORT, stats["reads"]))

    if timed_out:
        if not JSON_OUT:
            print("timeout after %.1fs" % TIMEOUT, flush=True)
        _emit({"type": "timeout", "after": TIMEOUT})
        sys.exit(124)

    _log("parsing packets")
    seen = set()
    parsed = []
    for p in pkts:
        ihl = (p[14] & 0x0F) * 4
        tcp_off = 14 + ihl
        sp, dp, sq = struct.unpack("!HHI", p[tcp_off:tcp_off + 8])
        doff = (p[tcp_off + 12] >> 4) * 4
        off = tcp_off + doff
        fl = p[tcp_off + 13]
        pl = len(p) - off
        k = (sp, dp, sq, pl)
        if k in seen:
            continue
        seen.add(k)
        parsed.append((sp, dp, sq, pl, off, fl, p))
    _log("parsed %d unique packets" % len(parsed))

    _log("reading strace log")
    sends = []
    with open(LOG) as f:
        for line in f:
            m = re.search(r"socket:\[(\d+)\]", line)
            n = re.search(r"=\s*(\d+)\s*$", line)
            if m and n and "send" in line:
                sends.append((m.group(1), int(n.group(1))))
    _log("read %d send() calls" % len(sends))

    _log("matching")
    matched = 0
    printed_inodes = set()
    for ino, nb in sends:
        if not JSON_OUT:
            print("sendto", nb, "bytes", flush=True)
        if ino not in conns:
            _log("inode %s not in conns, skipped" % ino)
            _emit({"type": "sendto", "bytes": nb, "matched": False})
            continue
        lh, lp = conns[ino][0].split(":")
        rh, rp = conns[ino][1].split(":")
        lport = int(lp, 16)
        rport = int(rp, 16)
        ls = "%d.%d.%d.%d:%d" % (
            int(lh[6:8], 16), int(lh[4:6], 16),
            int(lh[2:4], 16), int(lh[0:2], 16),
            int(lp, 16),
        )
        rs = "%d.%d.%d.%d:%d" % (
            int(rh[6:8], 16), int(rh[4:6], 16),
            int(rh[2:4], 16), int(rh[0:2], 16),
            int(rp, 16),
        )
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
                fs = _flags(fl)
                if not JSON_OUT:
                    fs_s = "-".join(fs) if fs else "NONE"
                    if pl == 0:
                        print("  %s ->" % fs_s, lport, "->", rport, "seq", sq, flush=True)
                    else:
                        print(
                            "  %s ->" % fs_s, lport, "->", rport,
                            "seq", sq, "payload", pl,
                            repr(p[off:off + pl]),
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
        hit = False
        for sq, pl, off, fl, p in events:
            if pl == nb:
                matched += 1
                hit = True
                break
        _emit({"type": "sendto", "bytes": nb, "matched": hit})
    _log("matched %d sendto calls" % matched)

    if matched == 0:
        _log("no match, exit 1")
        sys.exit(1)

except KeyboardInterrupt:
    if not JSON_OUT:
        print("\ninterrupted", flush=True)
    _emit({"type": "interrupted"})
    sys.exit(130)

except Exception as e:
    sys.stderr.write("error: %s: %s\n" % (type(e).__name__, e))
    sys.exit(1)

finally:
    _log("entering finally")
    stop_capture.set()
    if cap_thread is not None:
        cap_thread.join(timeout=2)
    if st is not None:
        try:
            st.kill()
            st.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
    if srv is not None:
        try:
            srv.kill()
            srv.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
    if sn is not None:
        try:
            sn.close()
        except OSError:
            pass
    try:
        if os.path.exists(LOG):
            os.remove(LOG)
    except OSError:
        pass
    _log("cleanup done")

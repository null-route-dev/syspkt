import os
import sys
import re
import socket
import struct
import subprocess
import time

START = time.time()
VERBOSE = False


def _log(msg):
    if VERBOSE:
        sys.stderr.write("[%7.3f] %s\n" % (time.time() - START, msg))
        sys.stderr.flush()


raw = []
for a in sys.argv[1:]:
    if a in ("-v", "--verbose"):
        VERBOSE = True
    else:
        raw.append(a)

HOST = raw[0] if len(raw) > 0 else "127.0.0.1"
PORT = int(raw[1]) if len(raw) > 1 else 9999
MSG = raw[2].encode() if len(raw) > 2 else b"hello"
LOG = "/tmp/t.log"

_log("verbose on")
_log("host=%s port=%d msg=%r" % (HOST, PORT, MSG))
_log("log file=%s" % LOG)

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
    "import socket, struct, time; "
    "s=socket.create_connection((\"%s\", %d)); "
    "s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack(\"ii\", 1, 0)); "
    "time.sleep(1); "
    "s.send(b\"%s\"); "
    "s.close()"
) % (HOST, PORT, MSG.decode())

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
    _log("pkill done")
except FileNotFoundError:
    _log("pkill not found, skipped")
except subprocess.TimeoutExpired:
    _log("pkill timed out, skipped")

srv = None
st = None
sn = None

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

    _log("binding raw socket on lo")
    sn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sn.bind(("lo", 0))
    sn.settimeout(.1)
    _log("raw socket bound")

    _log("spawning strace")
    st = subprocess.Popen(
        [
            "strace", "-f", "-y", "-e", "trace=%network",
            "-o", LOG, "python3", "-c", CLI_CODE,
        ],
    )
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
        time.sleep(.05)
    _log("collected %d conns" % len(conns))

    _log("waiting for strace")
    st_start = time.time()
    while True:
        try:
            st.wait(timeout=0.5)
            _log("strace finished rc=%d after %.2fs" % (st.returncode, time.time() - st_start))
            break
        except subprocess.TimeoutExpired:
            _log("strace still running, t=%.1fs" % (time.time() - st_start))
    st = None

    _log("capturing packets")
    pkts = []
    try:
        while True:
            pkts.append(sn.recvfrom(65535)[0])
    except socket.timeout:
        pass
    sn.close()
    sn = None
    _log("captured %d packets" % len(pkts))

    _log("parsing packets")
    seen = set()
    parsed = []
    for p in pkts:
        if len(p) < 54:
            continue
        if p[12:14] != b"\x08\x00":
            continue
        if p[23] != 6:
            continue
        ihl = (p[14] & 0x0F) * 4
        tcp_off = 14 + ihl
        if len(p) < tcp_off + 20:
            continue
        sp, dp, sq = struct.unpack("!HHI", p[tcp_off:tcp_off + 8])
        doff = (p[tcp_off + 12] >> 4) * 4
        off = tcp_off + doff
        fl = p[tcp_off + 13]
        pl = len(p) - off
        k = (sp, dp, sq, pl)
        if k in seen:
            continue
        seen.add(k)
        if PORT in (sp, dp):
            parsed.append((sp, dp, sq, pl, off, fl, p))
    _log("parsed %d tcp packets on port %d" % (len(parsed), PORT))

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
        print("sendto", nb, "bytes", flush=True)
        if ino not in conns:
            _log("inode %s not in conns, skipped" % ino)
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
        print("  conn", ls, "->", rs, flush=True)
        events = []
        for sp, dp, sq, pl, off, fl, p in parsed:
            if sp == lport and dp == rport:
                events.append((sq, pl, off, fl, p))
        events.sort()
        if ino not in printed_inodes:
            printed_inodes.add(ino)
            for sq, pl, off, fl, p in events:
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
                fs = "-".join(fs) if fs else "NONE"
                if pl == 0:
                    print("  %s ->" % fs, lport, "->", rport, "seq", sq, flush=True)
                else:
                    print(
                        "  %s ->" % fs, lport, "->", rport,
                        "seq", sq, "payload", pl,
                        repr(p[off:off + pl]),
                        flush=True,
                    )
        for sq, pl, off, fl, p in events:
            if pl == nb:
                matched += 1
                break
    _log("matched %d sendto calls" % matched)

    if matched == 0:
        _log("no match, exit 1")
        sys.exit(1)

except KeyboardInterrupt:
    print("\ninterrupted", flush=True)
    sys.exit(130)

except Exception as e:
    sys.stderr.write("error: %s: %s\n" % (type(e).__name__, e))
    sys.exit(1)

finally:
    _log("entering finally")
    if st is not None:
        _log("killing strace pid=%d" % st.pid)
        try:
            st.kill()
        except OSError:
            pass
        try:
            st.wait(timeout=2)
            _log("strace reaped")
        except subprocess.TimeoutExpired:
            _log("strace did not exit after kill")
    if srv is not None:
        _log("killing server pid=%d" % srv.pid)
        try:
            srv.kill()
        except OSError:
            pass
        try:
            srv.wait(timeout=2)
            _log("server reaped")
        except subprocess.TimeoutExpired:
            _log("server did not exit after kill")
    if sn is not None:
        _log("closing raw socket")
        try:
            sn.close()
        except OSError:
            pass
    _log("removing log")
    try:
        if os.path.exists(LOG):
            os.remove(LOG)
    except OSError as e:
        _log("remove failed: %s" % e)
    _log("cleanup done")

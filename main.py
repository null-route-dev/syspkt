import os
import sys
import re
import socket
import struct
import subprocess
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
MSG = sys.argv[3].encode() if len(sys.argv) > 3 else b"hello"
LOG = "/tmp/t.log"

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

print("start")

subprocess.run(
    [
        "pkill", "-f",
        "s\\.setsockopt\\(socket\\.SOL_SOCKET, "
        "socket\\.SO_REUSEADDR, 1\\)",
    ],
    capture_output=True,
)

srv = None
st = None
sn = None

try:
    if os.path.exists(LOG):
        os.remove(LOG)

    srv = subprocess.Popen(
        ["python3", "-c", SRV_CODE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(.5)

    sn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sn.bind(("lo", 0))
    sn.settimeout(.1)

    st = subprocess.Popen(
        [
            "strace", "-f", "-y", "-e", "trace=%network",
            "-o", LOG, "python3", "-c", CLI_CODE,
        ],
    )

    conns = {}
    for _ in range(30):
        with open("/proc/net/tcp") as f:
            for r in f.read().split("\n")[1:]:
                p = r.split()
                if len(p) > 9:
                    conns[p[9]] = (p[1], p[2])
        time.sleep(.05)

    st.wait()
    st = None

    pkts = []
    try:
        while True:
            pkts.append(sn.recvfrom(65535)[0])
    except socket.timeout:
        pass
    sn.close()
    sn = None

    seen = set()
    parsed = []
    for p in pkts:
        if len(p) > 40 and p[23] == 6:
            sp, dp, sq = struct.unpack("!HHI", p[34:42])
            ihl = (p[14] & 0x0F) * 4
            doff = (p[14 + ihl + 12] >> 4) * 4
            off = 14 + ihl + doff
            pl = len(p) - off
            k = (sp, dp, sq, pl)
            if k in seen:
                continue
            seen.add(k)
            if PORT in (sp, dp):
                parsed.append((sp, dp, sq, pl, off, p))

    sends = []
    with open(LOG) as f:
        for line in f:
            m = re.search(r"socket:\[(\d+)\]", line)
            n = re.search(r"=\s*(\d+)\s*$", line)
            if m and n and "send" in line:
                sends.append((m.group(1), int(n.group(1))))

    for ino, nb in sends:
        print("sendto", nb, "bytes")
        if ino in conns:
            lh, lp = conns[ino][0].split(":")
            rh, rp = conns[ino][1].split(":")
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
            print("  conn", ls, "->", rs)
        for sp, dp, sq, pl, off, p in parsed:
            if pl == nb:
                d = "->" if dp == PORT else "<-"
                print(
                    "  pkt", d, sp, "->", dp,
                    "seq", sq, "payload", pl, repr(p[off:off + pl]),
                )
finally:
    if st is not None:
        st.kill()
        st.wait()
    if srv is not None:
        srv.kill()
        srv.wait()
    if sn is not None:
        sn.close()
    if os.path.exists(LOG):
        os.remove(LOG)

# syspkt

Correlates system calls with network packets.

## What it is

syspkt is a small tool that shows which `sendto()` call produced which TCP
packet. It runs a local echo server, traces a client under `strace`, sniffs
loopback with `AF_PACKET`, and matches them by socket inode and TCP sequence
number.

The output is a single timeline of syscalls and packets for one connection.

## How it works

syspkt watches three things at the same time:

- `strace -y` on the client, to see `sendto()` calls with socket inodes and
  return values
- `/proc/net/tcp`, to map socket inodes to `(src, dst)` 5-tuples
- `AF_PACKET` on `lo`, to capture the actual TCP segments

For each `sendto()`, it finds the matching connection and prints the full TCP
dialogue — `SYN`, `ACK`, `PSH-ACK`, `RST-ACK` — with the payload taken from
the wire.

No eBPF, no BCC, no kernel headers. Just `strace`, `procfs` and a raw socket.

## Status

Early development. Works for the demo scenario on loopback with TCP/IPv4.
Other protocols, other interfaces and multiple concurrent connections are
not handled yet.

## Requirements

- Linux
- Python 3.8+
- `strace` installed
- root or `CAP_NET_RAW` + `CAP_NET_ADMIN`

## Install

No package yet. Clone and run:

    git clone https://github.com/null-route-dev/syspkt
    cd syspkt

## Usage

Default demo (127.0.0.1:9999, message `hello`):

    sudo python3 main.py

Custom host, port and message:

    sudo python3 main.py 127.0.0.1 9999 test
    sudo python3 main.py 127.0.0.1 8080 'hi"there'

Verbose mode shows the progress of each step:

    sudo python3 main.py -v

## Example output

    $ sudo python3 main.py
    start
    sendto 5 bytes
      conn 127.0.0.1:42122 -> 127.0.0.1:9999
      SYN -> 42122 -> 9999 seq 4267321937
      ACK -> 42122 -> 9999 seq 4267321938
      PSH-ACK -> 42122 -> 9999 seq 4267321938 payload 5 b'hello'
      ACK -> 42122 -> 9999 seq 4267321943

Verbose mode:

    $ sudo python3 main.py -v
    [  0.000] verbose on
    [  0.000] host=127.0.0.1 port=9999 msg=b'hello'
    start
    [  0.015] spawning server
    [  0.015] server pid=461798
    [  0.520] capture thread started
    [  0.521] strace pid=461800
    [  2.103] strace finished rc=0 after 0.00s
    [  2.199] captured 16 packets on port 9999 (raw reads: 16)
    sendto 5 bytes
      conn 127.0.0.1:42132 -> 127.0.0.1:9999
      SYN -> 42132 -> 9999 seq 2300357909
      ACK -> 42132 -> 9999 seq 2300357910
      PSH-ACK -> 42132 -> 9999 seq 2300357910 payload 5 b'hello'
      RST-ACK -> 42132 -> 9999 seq 2300357915
    [  2.201] matched 1 sendto calls

## Exit codes

- `0` — at least one `sendto()` matched a packet
- `1` — nothing matched
- `130` — interrupted (Ctrl+C)

## Limitations

- Loopback only (`lo` interface)
- TCP over IPv4 only
- The client is hardcoded to a single `send()` after `sleep(1)`
- The server is a dumb echo that reads once and closes
- Multiple concurrent connections on the same port are not separated

## Contributing

Issues and pull requests are welcome.

## License

MIT License – see [LICENSE](LICENSE) for details.

#!/usr/bin/env python3
"""TCP client: connects, sends N ECHO messages, reports connect time, RTT and loss."""
import argparse
import socket
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', required=True)
    ap.add_argument('--port', type=int, default=5000)
    ap.add_argument('-n', type=int, default=10, help='number of messages')
    ap.add_argument('--interval', type=float, default=0.2)
    ap.add_argument('--timeout', type=float, default=3.0)
    ap.add_argument('--name', default=socket.gethostname())
    a = ap.parse_args()

    t0 = time.time()
    try:
        s = socket.create_connection((a.server, a.port), timeout=a.timeout)
    except OSError as exc:
        print(f'{t0:.3f} CONNECT_FAIL {a.server}:{a.port} ({exc})')
        return 1
    connect_ms = (time.time() - t0) * 1000
    print(f'{t0:.3f} CONNECTED {a.server}:{a.port} in {connect_ms:.1f} ms')

    rtts, sent = [], 0
    rf = s.makefile('r')
    try:
        s.sendall(f'HELLO {a.name}\n'.encode())
        print('server says:', rf.readline().strip())
        for i in range(a.n):
            t = time.time()
            s.sendall(f'ECHO msg-{i}\n'.encode())
            sent += 1
            if rf.readline():
                rtts.append((time.time() - t) * 1000)
            time.sleep(a.interval)
        s.sendall(b'BYE\n')
    except (socket.timeout, OSError) as exc:
        print(f'ERROR during session: {exc}')
    finally:
        s.close()

    loss = 100.0 * (sent - len(rtts)) / sent if sent else 100.0
    if rtts:
        print(f'sent={sent} recv={len(rtts)} loss={loss:.1f}% rtt min/avg/max = '
              f'{min(rtts):.2f}/{sum(rtts) / len(rtts):.2f}/{max(rtts):.2f} ms')
    else:
        print(f'sent={sent} recv=0 loss=100%')
    return 0


if __name__ == '__main__':
    sys.exit(main())

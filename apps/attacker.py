#!/usr/bin/env python3
"""Port scanner / connection flooder used to trigger the firewall (run from h3)."""
import argparse
import socket
import time


def parse_ports(spec):
    out = []
    for part in spec.split(','):
        if '-' in part:
            lo, hi = part.split('-')
            out.extend(range(int(lo), int(hi) + 1))
        else:
            out.append(int(part))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', required=True)
    ap.add_argument('--ports', default='6000-6010')
    ap.add_argument('--timeout', type=float, default=0.5)
    ap.add_argument('--delay', type=float, default=0.1)
    ap.add_argument('--rounds', type=int, default=1)
    a = ap.parse_args()
    ports = parse_ports(a.ports)
    print(f'{time.time():.3f} ATTACK_START {a.server} ports={a.ports} rounds={a.rounds}')
    for _ in range(a.rounds):
        for port in ports:
            t = time.time()
            try:
                socket.create_connection((a.server, port), timeout=a.timeout).close()
                res = 'OPEN'
            except socket.timeout:
                res = 'NO-REPLY (dropped/filtered)'
            except OSError as exc:
                res = f'REFUSED/ERR ({exc.errno})'
            print(f'{t:.3f} port {port}: {res}')
            time.sleep(a.delay)
    print(f'{time.time():.3f} ATTACK_END')


if __name__ == '__main__':
    main()

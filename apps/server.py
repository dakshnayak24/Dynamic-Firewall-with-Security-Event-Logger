#!/usr/bin/env python3
"""Multi-port threaded TCP server. Line protocol: HELLO <n> | ECHO <text> | TIME | BYE.
Port 5000 = 'data' service (open to all), port 6000 = 'admin' service (restricted by policy)."""
import argparse
import socket
import threading
import time

SERVICES = {5000: 'data', 6000: 'admin'}


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def handle(conn, addr, port):
    svc = SERVICES.get(port, 'svc')
    conn.settimeout(60)
    log(f'{svc}:{port} connection from {addr[0]}:{addr[1]}')
    try:
        with conn, conn.makefile('r') as rf:
            for line in rf:
                cmd, _, arg = line.strip().partition(' ')
                cmd = cmd.upper()
                if cmd == 'HELLO':
                    reply = f'OK {svc} welcome {arg}'
                elif cmd == 'ECHO':
                    reply = f'ECHO {arg}'
                elif cmd == 'TIME':
                    reply = f'TIME {time.time():.6f}'
                elif cmd == 'BYE':
                    conn.sendall(b'BYE\n')
                    break
                else:
                    reply = 'ERR unknown command'
                conn.sendall((reply + '\n').encode())
    except (socket.timeout, OSError) as exc:
        log(f'{svc}:{port} {addr[0]} error: {exc}')
    log(f'{svc}:{port} {addr[0]} closed')


def listen(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(128)
    log(f'listening on {host}:{port}')
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr, port), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='0.0.0.0')
    ap.add_argument('--ports', type=int, nargs='+', default=[5000, 6000])
    a = ap.parse_args()
    for port in a.ports:
        threading.Thread(target=listen, args=(a.host, port), daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()

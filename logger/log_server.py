#!/usr/bin/env python3
"""Centralised security-event logger: TCP server, one JSON event per line, many clients."""
import argparse
import json
import os
import socket
import threading
import time

lock = threading.Lock()


def handle(conn, addr, out):
    with conn, conn.makefile('r') as rf:
        for line in rf:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                ev = {'event': 'RAW', 'raw': line}
            ev['received_at'] = time.time()
            ev['from'] = addr[0]
            detail = {k: v for k, v in ev.items() if k not in ('event', 'ts', 'received_at', 'from')}
            with lock:
                out.write(json.dumps(ev) + '\n')
                out.flush()
                print(f"[{time.strftime('%H:%M:%S')}] {str(ev.get('event')):<16} {detail}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=9999)
    ap.add_argument('--file', default='logs/security_events.log')
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.file) or '.', exist_ok=True)
    out = open(a.file, 'a')
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.host, a.port))
    srv.listen(64)
    print(f'logger listening on {a.host}:{a.port}, writing {a.file}', flush=True)
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr, out), daemon=True).start()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()

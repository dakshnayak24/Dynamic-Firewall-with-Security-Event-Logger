#!/usr/bin/env python3
"""Mininet topology: 1 OVS switch (OpenFlow 1.3) + remote Ryu controller.
h1, h2 = legitimate clients, h3 = attacker, h4 = server (ports 5000, 6000).
Run from the repo root:  sudo python3 topo/fw_topo.py"""
import argparse
import os
from functools import partial

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ofport', type=int, default=6653)
    ap.add_argument('--bw', type=float, default=None, help='link bandwidth in Mbit/s')
    ap.add_argument('--delay', default=None, help="link delay, e.g. '5ms'")
    ap.add_argument('--loss', type=float, default=None, help='link loss in percent')
    a = ap.parse_args()

    setLogLevel('info')
    os.makedirs(os.path.join(ROOT, 'logs'), exist_ok=True)
    net = Mininet(controller=None, link=TCLink, autoSetMacs=True,
                  switch=partial(OVSKernelSwitch, protocols='OpenFlow13'))
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=a.ofport)
    s1 = net.addSwitch('s1')
    hosts = [net.addHost(f'h{i}', ip=f'10.0.0.{i}/24') for i in range(1, 5)]
    for h in hosts:
        net.addLink(h, s1, bw=a.bw, delay=a.delay, loss=a.loss)
    net.start()
    if hasattr(net, 'waitConnected'):
        net.waitConnected()

    h4 = net.get('h4')
    h4.cmd(f'python3 {ROOT}/apps/server.py --ports 5000 6000 > {ROOT}/logs/server.log 2>&1 &')
    info('*** server running on h4 (10.0.0.4) ports 5000,6000\n')
    CLI(net)
    net.stop()
    os.system('pkill -f apps/server.py')


if __name__ == '__main__':
    main()

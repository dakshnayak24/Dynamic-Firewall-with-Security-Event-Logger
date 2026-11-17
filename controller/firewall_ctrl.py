"""Dynamic SDN firewall (Ryu, OpenFlow 1.3).

- Classifies every new TCP flow by (src, dst, dst-port) against config/policy.json
- allow  -> installs forward + return flows on the switch
- deny   -> dropped at the controller; counted per source
- too many denies in a window -> source is BLOCKED (drop flow, hard timeout)
- when the block flow expires -> source RECOVERS automatically
- every security event is sent as a JSON line to the TCP logger server
Edit policy.json while running: it is reloaded automatically.
"""
import json
import os
import socket
import time
from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp, ether_types, in_proto
from ryu.ofproto import ofproto_v1_3

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY_FILE = os.environ.get('FW_POLICY', os.path.join(HERE, '..', 'config', 'policy.json'))
LOGGER_ADDR = (os.environ.get('FW_LOGGER_HOST', '127.0.0.1'),
               int(os.environ.get('FW_LOGGER_PORT', '9999')))

PRIO_ICMP, PRIO_TCP, PRIO_BLOCK = 5, 20, 100
FLOW_IDLE = 30
BLOCK_COOKIE = 0xB10C


class DynamicFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}                  # dpid -> {mac: port}
        self.policy = None
        self._policy_mtime = 0
        self.violations = defaultdict(deque)   # src ip -> timestamps of denies
        self.blocked = {}                      # src ip -> unblock time
        self.sessions = set()                  # (client, server, server_port) allowed
        self.log_q = hub.Queue(1000)
        self._load_policy()
        hub.spawn(self._log_sender)

    # ------------------------------------------------------------ logging
    def _event(self, etype, **fields):
        ev = {'ts': time.time(), 'event': etype}
        ev.update(fields)
        self.logger.info('%s', json.dumps(ev))
        try:
            self.log_q.put_nowait(ev)
        except hub.QueueFull:
            pass

    def _log_sender(self):
        """Ships events to the TCP logging server; reconnects if it goes away."""
        sock = None
        while True:
            ev = self.log_q.get()
            line = (json.dumps(ev) + '\n').encode()
            sent = False
            for _ in range(2):
                try:
                    if sock is None:
                        sock = socket.create_connection(LOGGER_ADDR, timeout=2)
                    sock.sendall(line)
                    sent = True
                    break
                except OSError:
                    if sock is not None:
                        try:
                            sock.close()
                        except OSError:
                            pass
                    sock = None
            if not sent:
                self.logger.warning('logger server unreachable; event kept in ryu log only')

    # ------------------------------------------------------------ policy
    def _load_policy(self):
        try:
            mtime = os.path.getmtime(POLICY_FILE)
            if mtime != self._policy_mtime:
                with open(POLICY_FILE) as f:
                    self.policy = json.load(f)
                first = self._policy_mtime == 0
                self._policy_mtime = mtime
                if not first:
                    self._event('POLICY_RELOAD', rules=len(self.policy.get('rules', [])),
                                auto_block=self.policy.get('auto_block', True))
        except (OSError, ValueError) as exc:
            self.logger.error('cannot load policy: %s', exc)
            if self.policy is None:
                self.policy = {'default_action': 'deny', 'auto_block': False, 'rules': []}

    def _classify(self, src, dst, dport):
        for rule in self.policy.get('rules', []):
            if (rule.get('src', 'any') in ('any', src) and
                    rule.get('dst', 'any') in ('any', dst) and
                    rule.get('dport', 'any') in ('any', dport)):
                return rule['action'], rule
        return self.policy.get('default_action', 'deny'), None

    # ------------------------------------------------------------ openflow helpers
    def _add_flow(self, dp, priority, match, actions, idle=0, hard=0, cookie=0, flags=0):
        ofp, p = dp.ofproto, dp.ofproto_parser
        inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst,
                                 idle_timeout=idle, hard_timeout=hard, cookie=cookie, flags=flags))

    def _tcp_flow(self, dp, src, dst, field, port, out_port):
        p = dp.ofproto_parser
        match = p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP,
                           ipv4_src=src, ipv4_dst=dst, **{field: port})
        self._add_flow(dp, PRIO_TCP, match, [p.OFPActionOutput(out_port)], idle=FLOW_IDLE)

    def _forward(self, dp, msg, in_port, out_port):
        ofp, p = dp.ofproto, dp.ofproto_parser
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
                                   actions=[p.OFPActionOutput(out_port)], data=data))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        ofp, p = dp.ofproto, dp.ofproto_parser
        self._add_flow(dp, 0, p.OFPMatch(),
                       [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        self._event('SWITCH_CONNECTED', dpid=dp.id)

    # ------------------------------------------------------------ main logic
    def _decide(self, ip, t):
        now = time.time()
        if ip.src in self.blocked:
            if self.blocked[ip.src] > now:
                return 'blocked', None
            del self.blocked[ip.src]
        if (ip.dst, ip.src, t.src_port) in self.sessions:     # reply of an allowed session
            return 'return', None
        action, rule = self._classify(ip.src, ip.dst, t.dst_port)
        return ('allow' if action == 'allow' else 'deny'), rule

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        self._load_policy()
        msg = ev.msg
        dp = msg.datapath
        ofp, p = dp.ofproto, dp.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofp.OFPP_FLOOD)
        known = out_port != ofp.OFPP_FLOOD

        ip = pkt.get_protocol(ipv4.ipv4)
        t = pkt.get_protocol(tcp.tcp)

        if ip and t:                                           # ---- TCP: firewalled
            verdict, rule = self._decide(ip, t)
            if verdict == 'allow':
                if (ip.src, ip.dst, t.dst_port) not in self.sessions:
                    self._event('ALLOW', src=ip.src, dst=ip.dst, dport=t.dst_port)
                self.sessions.add((ip.src, ip.dst, t.dst_port))
                if known:
                    self._tcp_flow(dp, ip.src, ip.dst, 'tcp_dst', t.dst_port, out_port)
                    self._tcp_flow(dp, ip.dst, ip.src, 'tcp_src', t.dst_port, in_port)
                self._forward(dp, msg, in_port, out_port)
            elif verdict == 'return':
                if known:
                    self._tcp_flow(dp, ip.src, ip.dst, 'tcp_src', t.src_port, out_port)
                self._forward(dp, msg, in_port, out_port)
            elif verdict == 'deny':
                self._on_violation(dp, ip, t, rule)
            return                                             # 'blocked' -> silent drop

        if ip and ip.src in self.blocked and self.blocked[ip.src] > time.time():
            return                                             # blocked host: no ICMP/UDP either

        if ip and ip.proto == in_proto.IPPROTO_ICMP and known:  # ---- ICMP: allowed
            match = p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_ICMP,
                               ipv4_src=ip.src, ipv4_dst=ip.dst)
            self._add_flow(dp, PRIO_ICMP, match, [p.OFPActionOutput(out_port)], idle=FLOW_IDLE)
        self._forward(dp, msg, in_port, out_port)              # ARP & others: learn/flood

    def _on_violation(self, dp, ip, t, rule):
        cfg = self.policy.get('block', {})
        now = time.time()
        dq = self.violations[ip.src]
        dq.append(now)
        while dq and now - dq[0] > cfg.get('window_s', 10):
            dq.popleft()
        self._event('DENY', src=ip.src, dst=ip.dst, dport=t.dst_port,
                    rule=rule, violations_in_window=len(dq))
        if (self.policy.get('auto_block', True) and len(dq) >= cfg.get('threshold', 5)
                and ip.src not in self.blocked):
            self._block(dp, ip.src, first_violation=dq[0])

    def _block(self, dp, src, first_violation):
        ofp, p = dp.ofproto, dp.ofproto_parser
        duration = self.policy.get('block', {}).get('duration_s', 30)
        now = time.time()
        self.blocked[src] = now + duration
        self.sessions = {s for s in self.sessions if s[0] != src}
        match = p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src)
        self._add_flow(dp, PRIO_BLOCK, match, [], hard=duration,
                       cookie=BLOCK_COOKIE, flags=ofp.OFPFF_SEND_FLOW_REM)
        self._event('BLOCK', src=src, duration_s=duration,
                    response_ms=round((now - first_violation) * 1000, 2))

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed(self, ev):
        msg = ev.msg
        if msg.cookie != BLOCK_COOKIE or 'ipv4_src' not in msg.match:
            return
        src = msg.match['ipv4_src']
        self.blocked.pop(src, None)
        self.violations.pop(src, None)
        self._event('RECOVER', src=src, blocked_for_s=msg.duration_sec)

# Dynamic Firewall with Security Event Logger (SDN + TCP sockets)

UE25CS243A SDN-Socket Programming mini project, topic 1.

## Architecture
```
 h1, h2 (clients)  --\
 h3 (attacker)     ---- s1 (OVS, OpenFlow 1.3) ---- h4 (TCP server :5000 data, :6000 admin)
                         |
                   Ryu controller  --(TCP, JSON lines)-->  logger/log_server.py (:9999)
```
1. Hosts exchange real TCP traffic (`apps/`).
2. The first packet of every flow goes to the controller, which classifies it by
   source, destination and port using `config/policy.json`.
3. allow -> forward and return flows installed. deny -> dropped and counted per source.
4. Too many denies in a time window -> the source is blocked with a drop flow (hard timeout).
5. When the block flow expires the controller logs RECOVER and the host regains access.
6. Every ALLOW / DENY / BLOCK / RECOVER event is sent over TCP to the central logger.

## Setup (Ubuntu 20.04/22.04 VM)
```
sudo apt update && sudo apt install -y mininet openvswitch-switch python3-pip
pip3 install ryu "eventlet==0.30.2"
ryu-manager --version
```
(On Ubuntu 22.04 if ryu-manager crashes at start: `pip3 install "setuptools==67.6.1"`.)

## Run (always from the repo root, three terminals)
```
T1: python3 logger/log_server.py
T2: ryu-manager --ofp-tcp-listen-port 6653 controller/firewall_ctrl.py
T3: sudo python3 topo/fw_topo.py
```
If a previous run crashed: `sudo mn -c`.

## Basic tests (inside the mininet> prompt)
| Test | Command | Expected |
|---|---|---|
| Connectivity | `pingall` | 0% dropped (ICMP allowed) |
| Allowed service | `h1 python3 apps/client.py --server 10.0.0.4 --port 5000 -n 5` | connects, loss 0% |
| Per-source rule | `h1 python3 apps/client.py --server 10.0.0.4 --port 6000` | allowed (h1 admin rule) |
| Denied | `h2 python3 apps/client.py --server 10.0.0.4 --port 6000` | CONNECT_FAIL, DENY in logger |
| Attack | `h3 python3 apps/attacker.py --server 10.0.0.4 --ports 6000-6010` | BLOCK event in logger |
| Blocked | `h3 ping -c 2 10.0.0.4` | 100% loss while blocked |
| Flow table | `sh ovs-ofctl -O OpenFlow13 dump-flows s1` | priority-100 drop flow for 10.0.0.3 |
| Recovery | wait 30 s, `h3 ping -c 2 10.0.0.4` | works again, RECOVER in logger |
| Dynamic policy | edit `config/policy.json` (e.g. allow h2 on 6000) | POLICY_RELOAD, takes effect without restart |

## Baseline for evaluation
Set `"auto_block": false` in policy.json for the static-firewall baseline (deny only, no automatic block).

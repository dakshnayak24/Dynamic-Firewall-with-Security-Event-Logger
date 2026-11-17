# Manual integration tests and demo

Run these tests in the Linux Mininet VM after following the root README. Commands below run at the `mininet>` prompt unless stated otherwise. Expected outcomes are test criteria, not recorded execution results.

## Preparation

1. Keep `config/policy.json` at its defaults and start a fresh controller and topology.
2. Start the logger before the controller, and save its output for the demo.
3. Test connectivity and allowed services before denied/attack traffic. Denied packets and retries accumulate per source, so use a fresh lab for independent cases.
4. Record Python, Ryu, Mininet, and Open vSwitch versions with the evidence.

## Core test cases

| ID | Scenario and command | Expected result / evidence |
| --- | --- | --- |
| T01 | `pingall` | All hosts reachable before any block. |
| T02 | `h1 python3 apps/client.py --server 10.0.0.4 --port 5000 -n 5` | Data greeting and five echo replies; `ALLOW` for the new session. |
| T03 | `h1 python3 apps/client.py --server 10.0.0.4 --port 6000 -n 5` | Admin service is permitted for `h1`. |
| T04 | `h2 python3 apps/client.py --server 10.0.0.4 --port 6000 -n 1` | Connection fails/times out; logger receives `DENY`. Retries may also reach the block threshold. |
| T05 | `h3 python3 apps/attacker.py --server 10.0.0.4 --ports 6000-6010` | Denied packets produce `BLOCK` after the configured threshold. |
| T06 | `sh ovs-ofctl -O OpenFlow13 dump-flows s1` immediately after T05 | Priority-100 IPv4 source drop for `10.0.0.3`, with a remaining hard timeout. |
| T07 | `h3 ping -c 2 10.0.0.4` while blocked | Source-wide IPv4 block drops ping. |
| T08 | `h1 python3 apps/client.py --server 10.0.0.4 --port 5000 -n 5` during `h3`'s block | Legitimate traffic remains allowed. Capture RTT and completion. |
| T09 | Wait at least 30 seconds from `BLOCK`, then `h3 ping -c 2 10.0.0.4` | `RECOVER` is logged and connectivity returns. |
| T10 | `h3 python3 apps/client.py --server 10.0.0.4 --port 5000 -n 5` after recovery | Allowed data access works again. |

## Multiple simultaneous clients

From a fresh lab, enter:

```text
h1 python3 apps/client.py --server 10.0.0.4 --port 5000 -n 20 > logs/h1_client.log 2>&1 &
h2 python3 apps/client.py --server 10.0.0.4 --port 5000 -n 20 > logs/h2_client.log 2>&1 &
```

Wait for both clients to finish, then inspect both log files from another VM terminal. Both should receive greetings and echo replies. Capture server output showing both client IPs.

## Runtime policy edit

Use a fresh lab so `h2` has no active source block. In another VM terminal, insert this rule **before** the broad admin deny in `config/policy.json`:

```json
{ "src": "10.0.0.2", "dst": "10.0.0.4", "dport": 6000, "action": "allow" }
```

Save, then run `h2 python3 apps/client.py --server 10.0.0.4 --port 6000 -n 5` in Mininet. Check for `POLICY_RELOAD` and a successful admin connection. Reload occurs on a controller packet-in, not immediately on save. Remove the added rule afterward. To verify a restrictive edit, restart the controller and topology: cached allow flows and return-session state are not invalidated on reload.

## Logger interruption

Stop the logger with Ctrl+C in Terminal 1, then generate a new denied request in Mininet. The controller should print the event locally and warn if delivery fails. Restart the logger and generate another new event. Confirm later events arrive. Events lost during the outage are not replayed.

## Cleanup and evidence

Type `exit` in Mininet. Stop the controller and logger with Ctrl+C. If a run crashed, execute `sudo mn -c` in the VM before restarting. Restore the default policy before each independent experiment.

Store chosen screenshots, terminal output, policy copies, and results under `docs/results/`. Runtime files in `logs/` are ignored by Git. The [evaluation guide](../docs/EVALUATION.md) describes the static comparison and metric definitions.

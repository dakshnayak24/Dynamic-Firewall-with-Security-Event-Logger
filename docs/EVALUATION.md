# Performance evaluation and static comparison

## Experiment design

Compare modes with the same TCP rules, traffic, topology, and VM resources:

- **Static baseline:** `"auto_block": false`. Unauthorized TCP is denied, but no automatic source-wide block is installed.
- **Dynamic firewall:** `"auto_block": true`, with 5 denied packets in 10 seconds and a 30-second block by default.

Restart the controller and topology between independent trials to clear sessions, violations, and switch flows. Save each policy with the evidence. Run at least five trials per condition and report individual values plus mean and range.

## Metrics

| Metric | Source / method | Interpretation |
| --- | --- | --- |
| Connect time (ms) | Client `CONNECTED` output | TCP connection setup |
| Application RTT min/avg/max (ms) | Client echo round trips | Response time for received replies |
| Message completion (%) | `recv / sent * 100` from client | Completed echo replies; not IP packet delivery |
| Block response (ms) | `BLOCK.response_ms` | Oldest retained denied packet to controller block decision, including threshold accumulation |
| Blocked duration (s) | `RECOVER.blocked_for_s` | Removed flow's duration, with integer-second resolution |
| Traffic impact | Legitimate client metrics during scan | Compare matched static/dynamic trials |

The implementation does not collect byte throughput, exact switch enforcement delay, jitter, or IP packet loss. Add explicit instrumentation before claiming those metrics. A flow dump confirms rule presence at inspection time, not its exact activation time.

## Conditions and procedure

1. Test normal traffic with both legitimate clients on port 5000.
2. Repeat while `h3` scans ports 6000-6010.
3. Repeat with controlled bandwidth, delay, or loss, for example:

   ```bash
   sudo python3 topo/fw_topo.py --bw 10 --delay 5ms --loss 1
   ```

   Settings apply to each host-switch link. `--delay 5ms` is not itself the end-to-end RTT. Keep parameters fixed between paired modes.

4. Start a fresh lab and use a distinct logger output file for every trial because the logger appends:

   ```bash
   python3 logger/log_server.py --host 127.0.0.1 --file docs/results/dynamic-trial-01-events.jsonl
   ```

5. Run `pingall`, then start legitimate clients at the Mininet prompt:

   ```text
   h1 python3 apps/client.py --server 10.0.0.4 --port 5000 -n 200 --interval 0.2 > logs/h1_client.log 2>&1 &
   h2 python3 apps/client.py --server 10.0.0.4 --port 5000 -n 200 --interval 0.2 > logs/h2_client.log 2>&1 &
   ```

6. For scan conditions, immediately run the same scan in both modes:

   ```text
   h3 python3 apps/attacker.py --server 10.0.0.4 --ports 6000-6010 --rounds 3
   sh ovs-ofctl -O OpenFlow13 dump-flows s1
   ```

7. Let clients finish. Copy their logs into uniquely named files under `docs/results/` before the next run overwrites them. Capture block/recovery events and verify restored connectivity after expiry.
8. For the static baseline, record block response/duration as **not applicable**, rather than zero. Admin requests should still fail, while ping is not source-blocked.
9. Save environment versions, link settings, policy, raw logs, flow dumps, and unexpected behavior. Repeat in the other mode and across trials.

Repeated scan rounds may continue past a recovery boundary. Use event timestamps to distinguish separate block episodes.

## Results to populate

No measurements were supplied with the archive. Replace placeholders only with observed values.

| Condition | Mode | Trial | Client connect ms | Client average RTT ms | Echo sent / received | Block response ms | Blocked duration s |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Normal | Static | To measure | To measure | To measure | To measure | n.a. | n.a. |
| Normal | Dynamic | To measure | To measure | To measure | To measure | n.a. | n.a. |
| Scan | Static | To measure | To measure | To measure | To measure | n.a. | n.a. |
| Scan | Dynamic | To measure | To measure | To measure | To measure | To measure | To measure |

Use separate client rows where appropriate. Graph legitimate-client average RTT by mode/condition and dynamic block response across trials. Explain TCP retries, VM load, threshold timing, and link impairment when interpreting results. A one-switch topology does not demonstrate alternate-path recovery.

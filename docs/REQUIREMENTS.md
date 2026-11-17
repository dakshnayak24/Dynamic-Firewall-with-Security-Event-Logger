# Project expectations and rubric mapping

The supplied [project workbook](reference/SDN_Socket_Programming_30_Projects.xlsx), sheet **30 Projects**, cells **A2:E2**, identifies Project 1 as **Dynamic Firewall with Security Event Logger**, using **TCP**. The task combines socket-generated application traffic, SDN allow/deny/block decisions, and centralized socket logging.

| Expectation | Implementation / procedure | Evidence to collect in the VM |
| --- | --- | --- |
| TCP client/server communication | `apps/client.py`, `apps/server.py` | Greeting, echo exchanges, timing output |
| Classify source, destination, port | Controller and `config/policy.json` | Different outcomes for `h1`/`h2` on port 6000 |
| Dynamic SDN firewall rules | Flow installation and block timeout | OVS flow table before, during, after block |
| Central event logger | `logger/log_server.py`, controller sender | JSON-lines log with matching source/timestamps |
| Multiple clients | Threaded server and logger | Concurrent `h1`/`h2` data sessions |
| Automatic blocking and recovery | Violation window, drop timeout, flow-removed handler | `DENY`, `BLOCK`, `RECOVER` and connectivity tests |
| Response time and network impact | `response_ms`, client metrics, evaluation guide | Repeated measurements and static comparison |

The [guidelines PDF](reference/SDN-Socket%20Programming-Guidelines_Rubrics.pdf) requires a Mininet-based socket application integrated with SDN, multiple communicating nodes where applicable, topology, source, configuration, test cases, reproducible instructions, and documented GitHub demo code. This repository provides implementation and procedures. End-to-end execution and measured performance evidence must still be collected in the lab.

## Grading rubric

| Deliverable | Component | Marks | Material / required demo evidence |
| --- | --- | ---: | --- |
| D1 | Problem understanding and architecture | 2 | README, supplied architecture image |
| D1 | TCP/UDP socket implementation | 4 | TCP apps, threaded server, event logger |
| D1 | Mininet + SDN implementation | 4 | Topology, controller, OVS flow inspection |
| D1 | Socket-SDN integration | 3 | Request causes allow/deny/block and logged events |
| D1 | Initial testing and demo | 2 | `tests/README.md` and captured output |
| | **D1 total** | **15** | |
| D2 | Complete application functionality | 4 | Allowed/denied services, concurrent clients |
| D2 | Dynamic SDN functionality | 6 | Block, recovery, live rule addition |
| D2 | Challenging scenario / robustness | 4 | Controlled scan; legitimate client remains usable |
| D2 | Performance evaluation and comparison | 5 | `EVALUATION.md`, repeated trials, static baseline |
| D2 | Documentation, final demo and viva | 6 | Architecture, tests, results evidence, explanations |
| | **D2 total** | **25** | |
| | **Overall total** | **40** | |

This maps the supplied rubric to project material. It does not assign or predict a grade.

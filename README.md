# Zero Trust Driven Application Trust Establishment Framework in SDN

M.Tech research implementation: a Zero Trust verification layer between
network applications and the SDN controller. EVERY request from EVERY
application is verified before it can change the network - no request is
trusted by default ("Never Trust, Always Verify").

## Research Gap

Traditional SDN lets network applications talk to the controller through
the Northbound API with NO authentication, authorisation or trust checks.
Once an app is installed it is implicitly trusted like the controller
itself. This allows:

- Compromised apps to inject fake flow rules / modify network state
- Fake apps to impersonate legitimate services
- Replay attacks that reuse captured tokens
- Apps to execute operations far beyond their intended function

Existing defences (FortNox, Rosemary, PermOF) authenticate or contain app
behaviour, but none combine continuous verification + dynamic policy +
behavioural trust scoring in one framework - that is the gap this project
fills (extends Aliyu et al., Computer Networks 2020, with Zero Trust
principles from NIST SP 800-207 / Syed et al., IEEE Access 2022).

## Architecture

```
Apps (h1..h3) --HTTP northbound--> ZeroTrustController (RYU + ZT modules)
   POST /zt/request -> Token -> API Key -> Device -> RBAC -> ABAC
                        -> Behavioural -> Trust Score -> Policy Engine -> PEP
                                        | allow          | deny
                                        v                v
                             apply OpenFlow flow_mod     HTTP 403 (switch untouched)
                                        |
                                        v
                             OVS switch (Mininet) <--OpenFlow 1.3--
```

Components:
- `controller/` - 7 verification layers, policy engine, administrator,
  enforcement point, trust scoring + RYU integration controller
  (`ryu_controller.py`, baseline `basic_controller.py`)
- `topology/`  - Mininet network (1 OVS switch, h1-h4)
- `apps/`      - legit app clients + 5 attack simulations (HTTP)
- `tests/`     - offline test suite + performance measurement
- `config/`    - policies.json, trusted_apps.json
- `setup/`     - one-shot dependency installer
- `results/`   - JSON measurement outputs
- `docs/`      - architecture, pseudocode, paper sections, LaTeX paper

## Quick Start (Ubuntu VM)

### 1. Install dependencies
```bash
sudo bash setup/install_dependencies.sh
```

### 2. Offline tests (no network needed - verifies ZT logic)
```bash
python3 tests/run_all_tests.py      # legit apps ALLOWED, attacks BLOCKED
python3 tests/test_performance.py   # latency / throughput / overhead
```

### 3. Live demo in Mininet (real SDN + OpenFlow)

Terminal A - start the Zero Trust controller:
```bash
sudo ryu-manager controller/ryu_controller.py
```

Terminal B - start the network:
```bash
sudo python3 topology/network_topology.py
```

From the Mininet CLI:
```bash
mininet> h1 ping h4                          # connectivity check
mininet> h1 python3 ../apps/http_app_client.py --app monitor
mininet> h2 python3 ../apps/http_app_client.py --app admin
mininet> h3 python3 ../apps/http_app_client.py --attack no_credentials
mininet> h3 python3 ../apps/http_app_client.py --attack fake
mininet> h3 python3 ../apps/http_app_client.py --attack replay
mininet> h3 python3 ../apps/http_app_client.py --attack unauthorized
mininet> h3 python3 ../apps/http_app_client.py --attack flood
```

Watch the controller log: ALLOWED / DENIED with trust scores and latencies.
Then inspect:
```bash
curl http://127.0.0.1:8080/zt/stats                # counters + avg latency
curl http://127.0.0.1:8080/zt/trust/legitimate_admin
sudo ovs-ofctl -O OpenFlow13 dump-flows s1         # ZT-approved flows only
```

### 4. Baseline vs Zero Trust comparison (for the paper)
```bash
# Baseline: run the plain controller and measure
sudo ryu-manager controller/basic_controller.py
# then repeat the same iperf3 tests:
#   mininet> h1 iperf3 -s &
#   mininet> h4 iperf3 -c 10.0.0.1 -t 10
# Compare with the Zero Trust controller run (step 3).
```

### 5. Notes
- Mininet/RYU need Linux (Ubuntu VM recommended on Windows hosts).
- The WSGI REST API listens on TCP 8080; OpenFlow on TCP 6653.
- Tokens are HMAC-SHA256(app_id:timestamp) and expire after 60 s.

## Evaluation Results (paper-ready, measured on Ubuntu VM)

| Metric | Result |
|---|---|
| Attack detection (5 classes, 50 runs each) | **100%** (no_credentials, fake_device, replay, unauthorized, flood) |
| False positive rate (legit monitor/admin) | **0.000** (0/50 each) |
| Flood request blocking | 0.600 (blocks from 7th request of burst) |
| Latency overhead vs baseline (avg) | **+1.48 ms (+37%)**, p95 +1.73 ms |
| Concurrent latency (10 workers) | 25.2 ms baseline → 50.2 ms ZT (eventlet GIL) |
| Scalability 4/8/16 hosts | ping loss **0.0%**, seq latency flat (~3.6 ms) |
| Trust evolution | admin 0.88→1.00, compromised 0.88→0.00 |

Reproduce with `tools/bench_phase_b.py` (B1 detection, B2 latency, B3 trust traces) and
`tools/bench_scalability.py` (B4). Raw data + figures in `results/`.

## Paper

IEEE-style manuscript (LaTeX + Markdown master): `paper/paper.md`, `paper/paper.tex`
with figures in `paper/figures/`. Compile `paper.tex` on Overleaf (IEEEtran built-in).
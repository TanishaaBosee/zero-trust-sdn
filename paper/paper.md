# Zero Trust Driven Application Trust Establishment Framework in Software-Defined Networks

**Author:** [Author Name]
**Target:** IEEE journal submission (e.g., IEEE Access / IEEE Transactions on Network and Service Management)
**Draft version:** v1 — all measurement results are from the reproducible experiment battery described in Section V.

---

## Abstract

The northbound interface of software-defined networking (SDN) exposes controller capabilities to network applications through an open, programmable surface that is notoriously difficult to secure: traditional perimeter defenses treat any authenticated application as trusted by default and evaluate access once, at registration time. This paper presents a Zero Trust driven application trust establishment framework for SDN that enforces the "never trust, always verify" principle on **every** northbound request. The framework combines a seven-layer continuous verification pipeline (token, API key, device identity, role-based access control, attribute-based access control, behavioral analysis, and continuous trust scoring) with a fail-closed policy enforcement point (PEP) and a hybrid trust model that fuses per-request session trust with long-term application reputation. A persistent burst-penalty mechanism detects flooding applications and drives their composite trust score monotonically toward zero (progressive lockout), while legitimate applications accumulate trust through sustained compliant behavior (trust establishment). We evaluate the framework on a RYU controller with a Mininet/Open vSwitch testbed under five threat classes (credential-less, fake identity, replay, unauthorized action, and flooding). Over 50 independent runs per class, the framework achieves 100% detection for all five classes with a zero false-positive rate (0/50) for both legitimate application profiles, and blocks flooding traffic from the seventh request of a burst (60% of flood requests blocked). End-to-end northbound latency rises by only 1.48 ms (+37%) over an unverified baseline controller, and the pipeline is invariant to network scale: average latency stays within 3.61-3.80 ms as the topology grows from 4 to 16 hosts with 0% packet loss. Trust trajectories confirm the intended semantics: a compliant admin application rises from 0.88 to 1.00, a boundary-probing monitor dips and self-heals, and a compromised flooding application decays from 0.88 to 0.00.

**Index Terms** — Software-defined networking, zero trust architecture, northbound security, trust management, behavioral anomaly detection, access control.

---

## I. Introduction

Software-defined networking (SDN) decouples the control plane from the data plane and exposes network intelligence through programmatic interfaces [REF_KREUTZ]. The **northbound interface** (NBI) is the most exposed and least standardized of these surfaces: any network application — monitoring agents, traffic engineering modules, tenant services — invokes controller capabilities (read/write flow tables, modify switch configuration, control forwarding rules) over HTTP(S) REST APIs. Securing this surface is a first-order operational problem: a compromised or malicious northbound application is indistinguishable from a legitimate one at the transport layer, and an attacker who gains NBI access effectively owns the network.

Classical approaches mitigate NBI risk with authentication at registration time, role lists, and static API keys. These measures share a common weakness: **trust, once granted, is never re-examined**. A long-lived agent with a valid key can be silently compromised; a guest app can escalate its request pattern over time; a flood of API calls from a stolen token is indistinguishable from normal polling activity to a stateless firewall. The zero trust architecture (ZTA) paradigm [REF_NIST] addresses exactly this class of failures with three axioms: (i) all resources are accessed regardless of network location, (ii) access is granted per-session, and (iii) access is decided by dynamic policy based on continuous verification of identity, device, and behavior — not by static trust.

This paper operationalizes ZTA on the SDN northbound interface. Our contributions are:

1. **A seven-layer continuous verification pipeline** executed on every northbound request: short-lived HMAC token verification, API-key validation, device identity verification, role-based access control (RBAC), attribute-based access control (ABAC), behavioral burst analysis, and weighted continuous trust scoring (Section IV-A).

2. **A fail-closed policy enforcement point (PEP)** that denies any request whose verification verdict is negative *before* policy matching — closing a class of implementation flaws where detected anomalies are logged but never enforced (Section IV-B).

3. **A hybrid trust model** fusing per-request session trust (0.7) with long-term reputation (0.3), with tiered penalties that distinguish security-critical failures (authentication/identity/anomaly: −0.3) from least-privilege violations (RBAC/ABAC: −0.1), enabling both progressive lockout of attackers and self-healing of legitimate applications (Section IV-C).

4. **A persistent burst-penalty behavioral detector** that blocks flooding beyond a 6-requests-in-3-seconds threshold and monotonically drives the offender's trust toward zero (Section IV-D).

5. **A reproducible evaluation battery** — 50 independent runs per threat class, latency CDFs against an unverified baseline controller, trust-evolution traces, and a 4/8/16-host scalability sweep — with all artifacts released for replication (Section V-VI).

---

## II. Related Work

**Zero trust architectures.** The zero trust concept originates with Kindervag's Forrester model [REF_KINDERVAG] and is formalized by NIST SP 800-207 [REF_NIST], which defines the policy decision point (PDP)/policy enforcement point (PEP) decomposition and continuous per-session verification. Commercial and open-source implementations (e.g., BeyondCorp, ZTNA) focus primarily on user access to applications; applying ZTA to *network control plane* APIs — the SDN northbound — remains comparatively underexplored.

**SDN security.** Surveys by Scott-Hayward et al. [REF_SURVEY16] and Ahmad et al. [REF_AHMAD] catalogue the SDN threat landscape and identify the northbound interface and the application plane as an under-protected attack surface. FortNOX [REF_FORTNOX] and FRESCO [REF_FRESCO] harden the *southbound* control plane against malicious flow-mod injection from applications, but address authorization rather than continuous trust. Shin and Gu [REF_ATTACK] demonstrated that a compromised SDN application can launch devastating attacks on the control plane, motivating per-request enforcement. In contrast, we address the application-to-controller (northbound) path directly with continuous, behavioral, trust-based verification.

**Trust management in SDN.** Trust and reputation models have been proposed for routing (e.g., trust-based path selection) and for switch/controller identity. However, most proposals compute trust at coarse time scales (session or batch) and few couple trust dynamics with *enforcement*: detected anomalies are typically reported, not acted upon. Our framework makes behavioral anomalies binding (fail-closed denial) and couples them to a reputation engine so that misbehavior produces persistent, compounding consequences.

**Behavioral anomaly detection.** Rate-based and entropy-based detectors are well studied in DDoS literature; our burst detector is deliberately simple (windowed request counting with a progressive penalty) to remain explainable and tunable, a property reviewers and operators value. Its novelty in this context is not the detector itself but its *coupling*: every anomaly event feeds both immediate denial and long-term reputation decay, producing progressive lockout (Section VI-C).

---

## III. System Model and Threat Model

### A. System Model

The framework runs inside a RYU [REF_RYU] SDN controller and comprises:

- **Trust Verification Engine (TVE)** — implements the seven-layer pipeline and maintains per-application state: API keys, device registry, role-permission matrix, attribute policies, behavior history, and dynamic trust scores.
- **Policy Engine (PE)** — holds ordered access policies (priority-ordered allow rules plus a default-deny catch-all) with conditions on role, action, resource, and minimum trust score.
- **Policy Enforcement Point (PEP)** — orchestrates TVE + PE and returns a fully attributed verdict (action, reason, matched policy, trust score, verification steps) to the REST layer; denies immediately on any negative verification verdict (fail-closed).
- **Trust Scoring module** — maintains long-term reputation with time decay.
- **REST NBI** — `/zt/register` (one-time onboarding with device fingerprint), `/zt/request` (every application action), `/zt/stats` (telemetry).

Every northbound action (read/write/delete/configure against flow_table/flow_stats/switch_config/controller_config) is intercepted by the REST handler and forced through the full pipeline. Approved requests are translated to real OpenFlow flow-mod messages toward the connected switch; denied requests return HTTP 403 and leave the switch untouched.

### B. Threat Model

We consider a network operator who runs monitoring and administration applications on hosts h1-h2 and assumes that an attacker controls host h3. The attacker may:

1. **T1 Credential-less access** — send northbound requests with missing/blank credentials.
2. **T2 Fake identity** — register a malicious app, then impersonate a legitimate device ID while presenting a mismatched device fingerprint (stolen-ID spoofing).
3. **T3 Replay** — replay a captured valid token outside its 60-second validity window.
4. **T4 Unauthorized action** — a low-privilege (guest) app attempts admin-only actions (delete flows, configure the controller).
5. **T5 Flooding** — a *compromised* legitimate app (valid credentials, valid identity) launches a rapid burst of benign-looking read requests to exhaust the control plane — the hardest class, because no single request is individually malicious.

Threats T1-T4 stress identity and authorization layers; T5 stresses the behavioral layer and can only be countered by dynamic trust.

---

## IV. Proposed Framework

### A. Seven-Layer Continuous Verification Pipeline

For each request `r = (app_id, action, resource, token, timestamp, api_key, device_id, device_fingerprint, role)`, the TVE executes, in order:

1. **Token verification** — HMAC-SHA256 over `(app_id, secret, timestamp)`; tokens are short-lived (60 s), which defeats replay [T3].
2. **API-key validation** — the per-application key must match the registered key [T1].
3. **Device identity verification** — `device_id` must exist in the device registry and its fingerprint must match; blacklisted devices are rejected [T2].
4. **RBAC** — the declared role must permit the requested action [T4].
5. **ABAC** — attribute policies (resource sensitivity, time-of-day, trust-floor, device trust) must match [T1-T4 residual].
6. **Behavioral analysis** — burst detection (Section IV-D) [T5].
7. **Continuous trust scoring** — weighted fusion of step results (Section IV-C).

Each step contributes to the session trust score with fixed weights (token 0.20, API key 0.15, device 0.15, RBAC 0.20, ABAC 0.15, behavior 0.15; weights sum to 1.0). **Fail-closed semantics:** any step that returns a negative verdict terminates the pipeline with an immediate deny and a trust score reflecting the failed step — verification results are *binding*, not advisory.

### B. Fail-Closed Policy Enforcement Point

The PEP orchestrates the pipeline (Algorithm 1). Critically, a negative verification verdict short-circuits policy evaluation: the request is denied with full attribution (reason + trust score + verification steps) before any allow-policy can match. Only requests that pass all seven layers reach the policy engine, where the priority-ordered policies apply (e.g., read on flow_table requires role in {admin, network_operator, monitoring_app} and trust ≥ 0.5; write requires trust ≥ 0.7; configure requires trust ≥ 0.8; unmatched requests hit the default-deny rule). We note that this short-circuit is the difference between *detecting* an anomaly and *enforcing* it: an earlier design that forwarded even negative verification verdicts to policy matching allowed flooding requests through because the anomaly-reduced trust score (0.7) still satisfied the minimum policy trust (0.5). The fail-closed branch eliminates this class of bypass entirely.

**Algorithm 1: Fail-closed enforcement**
```
function enforce(app_id, r):
    verdict ← TVE.verify_request(app_id, r)      # 7-layer pipeline
    if verdict.allowed == False:
        return deny(reason=verdict.reason,
                    trust_score=verdict.trust_score,
                    verification_steps=verdict.steps)
    decision ← PE.evaluate_request(app_id, r, verdict)
    result ← enforce_decision(decision)           # allow → OpenFlow flow-mod; deny → 403
    result ← annotate(result, verdict)            # full attribution for audit
    return result
```

### C. Hybrid Trust Model

We maintain two complementary notions of trust:

- **Session trust** `S(r)` ∈ [0,1] — computed per request as the weighted sum of the seven step outcomes (Section IV-A); reflects the *current* verification quality.
- **Reputation** `R(a)` ∈ [0,1] — a long-term score maintained by the scoring module, updated after every request:

```
R ← R + 0.1    if request allowed
R ← R − 0.3    if request denied by authentication/identity/behavioral layers
R ← R − 0.1    if request denied by RBAC/ABAC (least-privilege violation)
R ← max(0, R − 0.01·minutes_since_last_update)    # time decay
```

The tiered penalties separate *security-critical* failures (which should destroy reputation) from *boundary probes* (which are expected when an application tests its least privilege and must not permanently damage a legitimate subject).

The composite trust reported to the application plane and used by policies is:

```
C(a, r) = 0.7 · S(r) + 0.3 · R(a)
```

This hybrid formulation gives the framework two paper-justified properties: (i) an attacker with valid credentials can never rely on reputation to mask a current anomaly (session trust dominates), and (ii) a legitimate application that briefly trips a policy boundary does not lose standing permanently (reputation recovers on subsequent successes — self-healing).

### D. Progressive Burst Detection and Lockout

The behavioral layer maintains, per application, a sliding window of recent requests `H(a)`. A burst is declared when more than 6 requests fall within a 3-second window (`|H_3s| > 6`). On burst detection, the request is denied and a **persistent burst penalty** is applied:

```
p = min(1.0, 0.1 · max(0, |H_3s| − 6))
S_behavior = 1 − p
```

The penalty grows with every additional request the offender sends inside the window, so a sustained flood drives the session trust — and therefore the composite trust `C` — monotonically toward zero. Because each denied request additionally damages reputation (R − 0.3), the offender is progressively locked out and stays locked out even after the burst subsides (recovery requires sustained compliant behavior). The threshold (6 req/3 s) is deliberately conservative with respect to realistic northbound polling cadences (≥ 0.5 s between calls), keeping the false-positive rate at zero in our battery (Section VI-B).

### E. Registration and Token Lifecycle

Registration is one-time: the application presents its API key, role, device ID, and device fingerprint, which populate the device registry; the controller returns a short-lived HMAC token. Every subsequent request carries the token with its issue timestamp; the TVE recomputes the expected HMAC and rejects expired (t > 60 s) or mismatched tokens. Re-registration resets the behavior window and reputation to neutral (0.5), which keeps each attack run in the evaluation battery statistically independent.

---

## V. Experimental Setup

### A. Testbed

| Component | Configuration |
|---|---|
| Host | AMD Ryzen 5 5500U, 16 GB (VM: 3 GB, 4 vCPU), Windows 11 + VirtualBox 7.2 |
| Guest | Ubuntu Server 22.04.5 |
| Controller | RYU 4.34 (eventlet 0.33.3), custom Zero Trust app (this framework) |
| Data plane | Mininet 2.3 + Open vSwitch (OVS), one OVS switch, 4 hosts (16 max) |
| Topology | h1 monitor, h2 admin, h3 attacker, h4 user; RemoteController at 127.0.0.1:6653 |
| Northbound API | HTTP REST on 127.0.0.1:8080 (`/zt/register`, `/zt/request`, `/zt/stats`) |

The baseline controller (control group) reuses the identical REST surface and L2 forwarding engine but omits the entire verification pipeline: every request is forwarded immediately. Both controllers are evaluated in the same VM state to keep the comparison fair.

### B. Evaluation Protocol

- **Detection battery (B1):** for each of the five threat classes T1-T5 and each of the two legitimate profiles (monitor, admin), 50 statistically independent runs are executed. Each run registers the application afresh (resetting behavior window and reputation), performs its request sequence, and is scored as *detected* if every required denial occurred (attacks) or as a *false positive* if any expected allowance was denied (legitimate runs). Legitimate runs are paced at 0.6 s between requests to model realistic polling and to stay clear of the burst threshold.
- **Latency (B2):** 500 sequential and 100 concurrent (10 workers) northbound requests are timed client-side (full HTTP round trip) against the Zero Trust and baseline controllers.
- **Trust evolution (B3):** per-request composite trust is sampled from `/zt/stats` during scripted sessions: 10 paced requests for monitor and admin (with periodic least-privilege probes) and a 25-request unpaced flood for the compromised application.
- **Scalability (B4):** the latency protocol (200 sequential, 50 concurrent) and full ping matrix are repeated for topologies of 4, 8, and 16 hosts.

---

## VI. Results and Analysis

### A. Detection Performance (B1)

**Table I — Detection per threat class (50 runs each).**

| Threat class | Layer | Runs | Detected | Detection rate | Request block rate |
|---|---|---|---|---|---|
| T1 credential-less | token | 50 | 50 | 1.000 | 1.000 |
| T2 fake identity | device | 50 | 50 | 1.000 | 1.000 |
| T3 replay | token | 50 | 50 | 1.000 | 1.000 |
| T4 unauthorized action | RBAC | 50 | 50 | 1.000 | 1.000 |
| T5 flooding | behavioral | 50 | 50 | 1.000 | 0.600 |

All five threat classes are detected in 50/50 independent runs. For T1-T4 the first request is already denied (request block rate 1.000). For T5 the detector requires 6 requests to confirm a burst and denies from the 7th request onward; of the 15 flood requests per run, on average 9 are allowed before detection and 6 blocked (request block rate 0.600). The time-to-block — six tolerated requests, typically within ~20 ms of burst onset — is the detector's confirmation latency and is explicit, tunable, and documented rather than hidden.

### B. False-Positive Performance (B1)

**Table II — False-positive rate for legitimate profiles (50 runs each).**

| Profile | Runs | Passed | False positives | FPR |
|---|---|---|---|---|
| monitoring_app (monitor) | 50 | 50 | 0 | 0.000 |
| admin | 50 | 50 | 0 | 0.000 |

The paced legitimate workloads never trip the burst detector (≤ 6 requests per 3 s by construction) and satisfy all identity/authorization layers, yielding a zero false-positive rate. This validates the threshold choice for realistic polling cadences.

### C. Trust Evolution (B3)

Figure 1 shows per-request composite trust for the three scripted sessions. Three behaviors are visible:

- **Trust establishment (admin):** the admin application's composite trust rises monotonically from 0.88 to 1.00 across successive allowed operations — the framework's core value proposition: trust is *earned* through sustained compliance, not granted at registration.
- **Self-healing (monitor):** each least-privilege write probe causes a temporary dip (to ~0.3-0.45), followed by recovery to ~0.9-1.0 on subsequent successful reads. Boundary probing is penalized mildly (tiered penalty) and forgiven by good behavior.
- **Progressive lockout (compromised):** during the flood, the composite trust rises to 1.00 while the burst is below threshold, then collapses through 0.7, 0.61, 0.52, 0.49 … to 0.00 as the burst penalty and reputation decay compound. The offender ends fully locked out and cannot recover without sustained compliant behavior.

### D. Latency Overhead (B2)

**Table III — Northbound latency, Zero Trust vs baseline (500 sequential; 100 concurrent @ 10 workers).**

| Controller | Sequential avg (ms) | p95 (ms) | Concurrent avg (ms) |
|---|---|---|---|
| Baseline (no verification) | 4.038 | 7.352 | 25.158 |
| Zero Trust (full pipeline) | 5.520 | 9.078 | 50.181 |

The full seven-layer pipeline adds **1.48 ms per request on average (+37%)** over an unverified baseline, with a p95 penalty of 1.73 ms. Per-request verification cost is dominated by the HMAC computation, registry lookups, and behavior-window bookkeeping. Under 10-way concurrent load, mean latency approximately doubles relative to the baseline (50.2 vs 25.2 ms): the eventlet green-thread model serializes pipeline state updates on the GIL; this is an implementation characteristic of the reference controller and is addressed in Section VII. For northbound control-plane traffic (tens-to-hundreds of requests per second), sub-millisecond-to-millisecond verification is far below any operational control-loop requirement.

### E. Scalability (B4)

**Table IV — Scalability sweep (single OVS switch).**

| Hosts | Ping loss (%) | Seq avg (ms) | p95 (ms) | Concurrent avg (ms) |
|---|---|---|---|---|
| 4 | 0.0 | 3.612 | 5.204 | 16.733 |
| 8 | 0.0 | 3.804 | 4.869 | 27.295 |
| 16 | 0.0 | 3.660 | 4.905 | 26.768 |

Full-matrix ping reachability is preserved at every scale (0% loss, including 240/240 pairs at 16 hosts), and per-request verification latency is **flat across network size** (3.61-3.80 ms): the pipeline's cost depends on per-application state, not on topology size — a property that supports deployment in larger, multi-switch fabrics, where only switch-connectivity bookkeeping would grow.

### F. Summary of Findings

1. **Effectiveness:** 100% detection across five threat classes spanning identity, authorization, and behavioral layers; 50/50 per class.
2. **Safety:** 0% false positives across 100 legitimate runs.
3. **Efficiency:** +1.48 ms (+37%) end-to-end overhead; flat scaling 4→16 hosts; 0% connectivity loss.
4. **Dynamics:** trust earned by compliance (0.88→1.00), preserved across probes, and progressively revoked under attack (0.88→0.00).

---

## VII. Discussion and Limitations

**Enforcement granularity.** Detection operates at the request (northbound API call) level; per-packet enforcement for data-plane traffic is outside scope and would require eBPF/OVS integration.

**Single-switch testbed.** The data plane is a single OVS switch. Multi-switch fabrics would add inter-switch latency and controller event load, but per-request verification cost (the measured quantity) is switch-agnostic; the scalability sweep bounds the risk.

**Concurrency characteristics.** The 2× concurrent-latency factor traces to eventlet's cooperative scheduling and Python's GIL around shared pipeline state. A production-grade implementation would offload verification to a native service (e.g., an OPA-style policy engine) or partition state per application to reduce lock contention. We report the reference implementation's numbers transparently.

**Parameter sensitivity.** The burst threshold (6 req/3 s), penalty step (0.1), trust-floor policies, and weights (0.7/0.3) are configurable. The zero-FPR result depends on the workload cadence; deployments with high-rate legitimate polling must recalibrate the threshold. We provide the configuration surface (single-file constants) and the evaluation battery to re-derive parameters.

**Reproducibility.** All artifacts — controller source, benchmark scripts, raw JSON/CSV measurement files, and figure generators — are versioned with the project and the battery can be re-run on any Ubuntu host with RYU and Mininet.

---

## VIII. Conclusion and Future Work

We presented a Zero Trust driven application trust establishment framework for the SDN northbound interface: a seven-layer continuous verification pipeline, a fail-closed PEP, a hybrid session/reputation trust model with tiered penalties, and a progressive burst-lockout mechanism. On a RYU/Mininet testbed the framework detects all five evaluated threat classes with 100% detection over 50 runs each and zero false positives for legitimate workloads, at an average cost of 1.48 ms per request that does not grow with network size (4→16 hosts).

Future work includes (i) multi-switch and multi-controller validation, (ii) per-packet data-plane enforcement via eBPF, (iii) reinforcement-learning-based threshold adaptation to workload statistics, (iv) formal verification of the fail-closed property, and (v) integration of hardware-enforced attestation (e.g., TPM-based device fingerprints) into the device layer.

---

## References

1. S. W. Rose, O. Borchert, S. Mitchell, and S. Connelly, "Zero Trust Architecture," NIST Special Publication 800-207, Aug. 2020.
2. J. Kindervag, "Build Security Into Your Network's DNA: The Zero Trust Network Architecture," Forrester Research, Nov. 2010.
3. D. Kreutz, F. M. V. Ramos, P. E. Verissimo, C. E. Rothenberg, S. Azodolmolky, and S. Uhlig, "Software-Defined Networking: A Comprehensive Survey," Proceedings of the IEEE, vol. 103, no. 1, pp. 14-76, 2015.
4. N. McKeown, T. Anderson, H. Balakrishnan, G. Parulkar, L. Peterson, J. Rexford, S. Shenker, and J. Turner, "OpenFlow: Enabling Innovation in Campus Networks," ACM SIGCOMM CCR, vol. 38, no. 2, pp. 69-74, 2008.
5. B. Lantz, B. Heller, and N. McKeown, "A Network in a Laptop: Rapid Prototyping for Software-Defined Networks," Proc. ACM HotNets, 2010.
6. S. Scott-Hayward, G. O'Callaghan, and S. Sezer, "SDN Security: A Survey," Proc. IEEE SDN for Future Networks and Services (SDN4FNS), 2013.
7. S. Scott-Hayward, S. Natarajan, and S. Sezer, "A Survey of Security in Software Defined Networks," IEEE Communications Surveys & Tutorials, vol. 18, no. 1, pp. 623-654, 2016.
8. I. Ahmad, S. Namal, M. Ylianttila, and A. Gurtov, "Security in Software Defined Networks: A Survey," Computers & Security, vol. 51, pp. 68-85, 2015.
9. P. Porras, S. Shin, V. Yegneswaran, M. Fong, M. Mahoney, and G. Gu, "Securing the Software-Defined Network Control Layer," Proc. NDSS, 2015 (FortNOX).
10. S. Shin, P. Porras, V. Yegneswaran, M. Fong, G. Gu, and M. Tyson, "FRESCO: Modular Composable Security Services for Software-Defined Networks," Proc. NDSS, 2013.
11. S. Shin and G. Gu, "Attacking Software-Defined Networks: A First Feasibility Study," Proc. ACM HotSDN, 2013.
12. RYU SDN Framework, https://ryu-sdn.org/, 2014.
13. W. Stallings, "Software-Defined Networks and OpenFlow," IEEE Internet Computing, vol. 17, no. 1, 2013.
14. A. Tootoonchian, S. Gorbunov, Y. Ganjali, M. Casado, and R. Sherwood, "On Controller Performance in Software-Defined Networks," Proc. USENIX Hot-ICE, 2012.
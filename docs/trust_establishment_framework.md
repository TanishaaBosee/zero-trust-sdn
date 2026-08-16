# Trust Establishment Framework & Algorithm
## for Zero Trust Driven Application Trust Establishment in SDN

**Prepared for:** Discussion & finalization with supervisor (Dr. Tinku Singh)
**Basis:** Ideas adopted from Aliyu et al., *"A trust management framework for SDN
controller and network applications"*, Computer Networks 181 (2020) 107421 —
extended with Zero Trust principles (NIST SP 800-207): *no request is trusted
by default; every request is independently re-verified.*

---

## 1. Objective

Establish a dynamic, **continuously re-evaluated trust relationship** between
each network application and the SDN controller such that:

1. An application can modify the network **only after** passing
   *authentication* (identity), *authorisation* (permission) and *trust*
   (reliability) checks **on every request**.
2. The framework **establishes** trust for well-behaving applications
   (trust score rises with consistent policy conformant behaviour) and
   **revokes** trust for misbehaving applications (score falls, eventually
   blocking all access).
3. One-time authentication is **not enough** — a compromised application
   with valid credentials gets caught by continuous trust evaluation.

---

## 2. Framework Architecture (4 modules)

```
                +---------------------------------------------+
   App →        |  1. AUTHENTICATION MODULE                  |
 token, op,     |     - token = HMAC-SHA256(secret, app_id‖ts)|
 resource       |     - freshness window ΔT (replay defence)  |
                +---------------------+-----------------------+
                                      v
                +---------------------------------------------+
                |  2. AUTHORISATION MODULE (Boolean Access    |
                |     Matrix / BAM)                           |
                |     φ(app, op, resource) ∈ {0,1}            |
                +---------------------+-----------------------+
                                      v
                +---------------------------------------------+
                |  3. BEHAVIOURAL MODULE                      |
                |     - request rate, resource access pattern |
                |     - anomaly score η                       |
                +---------------------+-----------------------+
                                      v
                +---------------------------------------------+
                |  4. TRUST MODULE (continuous scoring)       |
                |     T  ∈ [0,1]  |  threshold θ(op)          |
                |     decision: T ≥ θ(op) → ALLOW             |
                |     otherwise → DENY                       |
                +---------------------+-----------------------+
                                      |
                       ALLOW → apply to controller (flow-mod)
                       DENY  → reject request + update T
```

---

## 3. Notations and Parameters

| Symbol | Meaning | Default (demo) |
|---|---|---|
| `A_i` | i-th network application | monitor, admin, attacker… |
| `S_i` | secret key of `A_i` (controller-side, never exposed) | random 32 hex |
| `T_i` | current trust score of `A_i`, range [0,1] | start 0.5 |
| `θ(op)` | minimum trust required for operation `op` | read 0.5, write 0.7, configure 0.8 |
| `θ_min` | global revocation threshold | 0.3 |
| `φ(op)` | Boolean Access Matrix entry (1 = allowed for app's role) | per role |
| `ΔT_tok` | token validity window (replay defence) | 60 s |
| `ΔT_rev` | mandatory re-authentication interval (continuous verify) | 60 s |
| `η` | anomaly score from behaviour analysis, [0,1] | — |
| `α` | trust reward per conformant request | 0.05 |
| `β` | trust penalty per violation/anomaly | 0.20 |
| `λ` | trust decay rate per idle minute (subjective-logic style discounting) | 0.01 |

**Trust representation (adopted from Subjective Logic in the SDN paper):**
`T` is the *projected belief* derived from opinion triple
`ω = (b, d, u)` — belief, disbelief, uncertainty —
`b + d + u = 1`, projected trust `T = b + a·u`, where `a` = base rate (0.5).
In the implementation we work directly with `T ∈ [0,1]` for simplicity;
the opinion triple is maintained for the belief/disbelief visualisation
expected in the paper (barycentric triangle).

---

## 4. Trust Establishment Algorithm (TEA)

### 4.1 Registration (one time — establishes the identity anchor)

```
ALGORITHM 1: REGISTER (offline, one-time)
INPUT : app_id, role, device fingerprint f
OUTPUT: secret S_i, initial trust T_i ↔ entry in BAM

1  if app_id ∈ Registry then return EXISTING_RECORD
2  generate secret S_i ← random(32 bytes)
3  initialise trust   T_i ← 0.5             // neutral: "trust but verify"
4  initialise opinion ω_i ← (b=0, d=0, u=1) // full uncertainty
5  set BAM role row: φ_i(op) = 1  for op ∈ RolePermissions(app_id)
6  store (app_id, S_i, role, f, T_i, ω_i, BAM_i)
7  issue first token: tok ← HMAC(S_i, app_id ‖ now)     // valid ΔT_tok
8  return (S_i, token, expiry)
```

### 4.2 Request verification (runs on EVERY request — zero trust core)

```
ALGORITHM 2: VERIFY_REQUEST — Trust Establishment at request time
INPUT : request r = (app_id, op, resource, token, ts, attrs)
OUTPUT: decision d ∈ {ALLOW, DENY} and updated trust T_i

1  if app_id ∉ Registry                  then return DENY("unknown app")
2  if |now − ts| > ΔT_tok                then DENY("token expired/replay");
                                                T_i ← T_i − β | update ω
3  if token ≠ HMAC(S_i, app_id ‖ ts)     then DENY("invalid signature");
                                                T_i ← T_i − β
4  if φ_i(op, resource) = 0              then DENY("access denied — BAM");
                                                T_i ← T_i − β
5  η ← BehaviourAnalysis(r, history_i)          // rate, pattern, novelty
6  if η > η_threshold                    then DENY("behaviour anomaly");
                                                T_i ← T_i − β
7  if T_i < θ(op)                        then DENY("insufficient trust");
                                                T_i ← T_i − β (decay)
8  ALLOW → apply op (controller executes)
9  T_i ← min(1, T_i + α)                        // reward, conformant
10 ω_i ← UpdateOpinion(ω_i, conform)
11 if T_i < θ_min                        then QUARANTINE(app_id)
12 log decision, trust and latency
13 return (ALLOW, T_i)
```

### 4.3 Continuous re-verification (between requests)

```
ALGORITHM 3: CONTINUOUS_MONITOR (periodic, every ΔT_rev)
INPUT : current sessions
OUTPUT: refreshed tokens or trust revocation

1  for each active app A_i do
2      if time since last request > ΔT_rev:
3          T_i ← T_i · e^(−λ · idle_minutes)        // trust decays
4          ω_i ← discount(ω_i, idle)                // uncertainty grows
5          expire token; app must re-authenticate   // "always verify"
6      if T_i < θ_min:
7          revoke token(s) of A_i; block A_i; alert
```

---

## 5. Design Rationale (why these decisions)

| Decision | Reason (from SDN paper / ZTA literature) |
|---|---|
| Token = HMAC(secret, app_id‖ts) | Paper: token-based authentication; HMAC+timestamp defeats replay within window; server-side secret means client can't forge |
| Token valid 60 s | Paper: "tokens are short-lived and must change after defined period" |
| BAM Boolean check `φ` | Paper: *Boolean Access Matrix* — "if function not captured in authorisation database, it cannot execute" |
| Trust = weighted opinion (b,d,u) | Paper: Subjective Logic reasoning — trust is not binary (0/1), decision space (0,1,[0..1]) |
| Trust threshold per operation θ(op) | Zero trust: least privilege — high-impact ops need higher trust (write 0.7, configure 0.8) |
| Reward α / penalty β asymmetry (β > α) | Trust is hard to gain, easy to lose (standard trust model property) |
| Time decay + forced re-auth | Zero trust continuous verification — a trusted app never stays "trusted forever" |
| Quarantine at θ_min | Paper: flag as malicious + deny all resources once trust collapses |

---

## 6. Worked Example (story of one request)

**Setup:** `monitor_app` (role: monitoring, φ = {read}), `admin_app` (role: admin,
φ = {read, write, configure}), attacker tries to delete flow table.

1. `monitor_app` requests `read flow_stats` → token valid ✓, BAM read ✓,
   T=0.5 ≥ θ(read)=0.5 ✓ → **ALLOW**, T → 0.55
2. `monitor_app` requests `write flow_table` → BAM write = 0 → **DENY**
   ("not captured in authorisation database") — least privilege enforced
3. `admin_app` requests `configure switch` → all checks pass, T=0.9 ≥ 0.8 →
   **ALLOW**, T → 0.95
4. Attacker (fake app, stolen token) sends `delete flow_table`:
   token signature fails (secret unknown) → **DENY**, T → 0.3 → next violation
   → quarantine
5. Compromised `admin_app` floods 15 `write` requests in 2 s → behaviour
   module η high → **DENY**; T falls below 0.7 → even valid writes now denied

**Result:** legitimate apps keep working (trust maintained), every attack
path is closed at a different layer (crypto / BAM / behaviour / trust).

---

## 7. Mapping to Implementation (existing codebase)

| Algorithm step | Implementation file / function |
|---|---|
| 1 Registration | `controller/trust_verification.py` → `register_application()` |
| 1,3 Token issue | `generate_token()` (HMAC-SHA256, 60 s expiry) |
| 2 Token verify | `_verify_token()` |
| 2 API/device gate | `_validate_api_key()`, `_verify_device_identity()` |
| 2 BAM / RBAC / ABAC | `_check_rbac()` + `controller/policy_engine.py` (POL-001…004) |
| 2 Behaviour | `_analyze_behavior()` (rate >10/5 s → anomaly) |
| 2 Trust decision | `_calculate_trust_score()` (weighted 7-layer) |
| 3 Decay/monitor | `controller/trust_scoring.py` → `update_score()` (decay 0.01/min) |
| Enforcement | `controller/policy_enforcement_point.py` → `enforce()` |
| SDN integration | `controller/ryu_controller.py` → `handle_northbound_request()` |

**Parameter defaults** live in `config/policies.json` (θ thresholds) and code
constants (α=0.1, β=0.3, λ=0.01 per trust_scoring.py).

---

## 8. What we need to finalize together (agenda for discussion)

1. Should trust be **per-operation threshold** (θ(op)) or single global θ?
2. Reward/penalty magnitude — β=0.2 per violation with α=0.05 reward (slow
   recovery) vs faster recovery?
3. Should the quarantine be permanent or time-based (e.g. 5 min cool-down)?
4. Do we keep the full Subjective Logic opinion (b,d,u) in the final paper,
   or is projected scalar T sufficient (paper is implementation-heavy)?
5. Baseline comparison metrics to report: throughput overhead, verification
   latency, detection rate table (we already measure all of these).
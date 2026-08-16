#!/usr/bin/env python3
"""
bench_phase_b.py - IEEE evaluation battery for the Zero Trust SDN framework.
Run with sudo:  sudo python3 bench_phase_b.py

Produces (in /home/tanis/bench_results):
  b1_detection.json   - 50-run per-threat-class detection battery
  b2_latency.json     - sequential + concurrent northbound latency (ZT vs baseline)
  b3_trust_trace.csv  - trust score evolution per application
  fig_trust.png       - trust evolution curves
  fig_latency.png     - latency CDF (Zero Trust vs baseline)
  fig_detection.png   - per-threat-class detection rate
"""
import os
import sys
import time
import json
import csv
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor

PROJECT = "/home/tanis/zero-trust-sdn"
CONTROLLER_DIR = os.path.join(PROJECT, "controller")
RESULTS = "/home/tanis/bench_results"
API = "http://127.0.0.1:8080"

sys.path.insert(0, os.path.join(PROJECT, "apps"))
from http_app_client import ZTClient, run_legit  # noqa: E402

os.makedirs(RESULTS, exist_ok=True)


def banner(title):
    print("\n" + "=" * 62)
    print("  " + title)
    print("=" * 62, flush=True)


def http_json(method, url, body=None, timeout=5):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.load(r)


def wait_api(endpoint, seconds=60):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(endpoint, timeout=2) as r:
                return json.load(r)
        except Exception:
            time.sleep(2)
    return None


def start_controller(controller_file):
    proc = subprocess.Popen(
        ["ryu-manager", controller_file],
        cwd=CONTROLLER_DIR,
        stdout=open("/tmp/bench_controller.log", "w"),
        stderr=subprocess.STDOUT)
    stats_url = (API + "/baseline/stats"
                 if controller_file == "baseline_controller.py"
                 else API + "/zt/stats")
    stats = wait_api(stats_url)
    if stats is None:
        raise RuntimeError("controller did not come up: " + controller_file)
    return proc


def start_topology():
    sys.path.insert(0, os.path.join(PROJECT, "topology"))
    from network_topology import ZeroTrustTopology
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
    net = Mininet(topo=ZeroTrustTopology(),
                  controller=lambda name: RemoteController(
                      name, ip="127.0.0.1", port=6653),
                  switch=OVSSwitch, build=True, autoSetMacs=True)
    net.start()
    time.sleep(4)
    return net


def stop_all(net, controller_procs):
    try:
        net.stop()
    except Exception:
        pass
    for proc in controller_procs:
        proc.terminate()


# ------------------------------------------------------------------
# B1: detection battery - 50 independent runs per threat class
# ------------------------------------------------------------------
def bench_detection():
    banner("B1: DETECTION BATTERY (50 INDEPENDENT RUNS PER CLASS)")
    attack_cases = {
        "no_credentials": "attack",
        "fake_device": "attack",
        "replay": "attack",
        "unauthorized": "attack",
        "flood": "attack",
    }
    legit_cases = {
        "monitor": "legit",
        "admin": "legit",
    }
    results = {"attacks": {}, "legit": {}}
    n_runs = 50

    def run_attack(name):
        denied, allowed = 0, 0
        for _ in range(n_runs):
            if name == "no_credentials":
                client = ZTClient("malicious_attacker")
                code = client._make_request("read", "flow_table",
                                            "install_flow", None, 2,
                                            token_override="")[0]
            elif name == "fake_device":
                client = ZTClient("fake_app")
                code = client._make_request(
                    "read", "flow_stats", "install_flow", None, 2,
                    role_override="monitoring_app",
                    device_id_override="device-001",
                    fingerprint_override=client.fingerprint)[0]
            elif name == "replay":
                client = ZTClient("malicious_attacker")
                code = client._make_request(
                    "read", "flow_table", "install_flow", None, 2,
                    token_override=client.token,
                    timestamp_override=client.token_timestamp - 120)[0]
            elif name == "unauthorized":
                client = ZTClient("malicious_attacker")
                code1 = client._make_request("delete", "flow_table",
                                             "install_flow", None, 2)[0]
                code2 = client._make_request("configure", "controller_config",
                                             "install_flow", None, 2)[0]
                denied = (code1 == 403) + (code2 == 403)
                allowed = (code1 == 200) + (code2 == 200)
                return denied, allowed
            elif name == "flood":
                client = ZTClient("compromised_app")
                for _ in range(15):
                    code = client._make_request("read", "flow_table",
                                                "install_flow", None, 2)[0]
                    if code == 403:
                        denied += 1
                    else:
                        allowed += 1
                return denied, allowed
            if code == 403:
                denied += 1
            else:
                allowed += 1
        return denied, allowed

    def run_legit_once(name):
        app_id = ("legitimate_monitor" if name == "monitor" else
                  "legitimate_admin")
        client = ZTClient(app_id)
        r1 = client._make_request("read", "flow_stats",
                                  "install_flow", None, 1)
        r2 = client._make_request("read", "flow_table",
                                  "install_flow", None, 1)
        r3 = client._make_request("write", "flow_table", "install_flow",
                                  {"eth_dst": "00:00:00:00:00:02"}, 1)
        return [r[0] for r in (r1, r2, r3)], (r1[1], r2[1], r3[1])

    def run_legit(name):
        allowed, denied = 0, 0
        for i in range(n_runs):
            codes, data = run_legit_once(name)
            if name == "monitor":
                ok = (codes[0] == 200 and codes[1] == 200 and
                      codes[2] == 403)
            else:
                ok = (codes[0] == 200 and codes[1] == 200 and
                      codes[2] == 200)
            if ok:
                allowed += 1
            else:
                denied += 1
                if denied <= 3:
                    print("    !!! %s run %d codes=%s reasons=%s" %
                          (name, i, codes,
                           [d.get("reason") for d in data]))
            time.sleep(0.6)
        return allowed, denied

    for name in attack_cases:
        denied, allowed = run_attack(name)
        detected = denied > 0
        results["attacks"][name] = {
            "runs": n_runs,
            "allowed": allowed,
            "denied": denied,
            "detected": detected,
            "detection_rate": round(detected, 3),
            "request_block_rate": round(
                denied / (allowed + denied), 3)
        }
        print("  %-14s runs=%d detected=%s rate=%.3f request_block=%.3f" %
              (name, n_runs, detected,
               results["attacks"][name]["detection_rate"],
               results["attacks"][name]["request_block_rate"]))
    for name in legit_cases:
        allowed, denied = run_legit(name)
        results["legit"][name] = {
            "runs": n_runs,
            "passed": allowed,
            "false_positive": denied,
            "false_positive_rate": round(denied / n_runs, 3)
        }
        print("  %-14s runs=%d false_positive=%d/%d (FPR=%.3f)" %
              (name, n_runs, denied, n_runs,
               results["legit"][name]["false_positive_rate"]))
    json.dump(results, open(os.path.join(RESULTS, "b1_detection.json"), "w"))
    return results


# ------------------------------------------------------------------
# B2: northbound latency - sequential + concurrent, ZT vs baseline
# ------------------------------------------------------------------
def bench_latency(kind):
    """kind = 'zt' (regular + concurrent against /zt/request via ZTClient)
       or 'baseline' (plain POSTs against /baseline/request)."""
    banner("B2: NORTHBOUND LATENCY (%s)" % kind)
    seq_n, conc_workers, conc_total = 500, 10, 100

    def one_post(_):
        t0 = time.time()
        client._make_request("read", "flow_stats", "install_flow", None, 1)
        return round((time.time() - t0) * 1000.0, 3)

    if kind == "zt":
        client = ZTClient("legitimate_monitor")
        seq = []
        for _ in range(seq_n):
            seq.append(one_post(None))
        with ThreadPoolExecutor(max_workers=conc_workers) as ex:
            conc = list(ex.map(one_post, range(conc_total)))
        label = "Zero Trust controller (/zt/request)"
    else:
        body = {"app_id": "legitimate_monitor", "action": "read",
                "resource": "flow_stats"}

        def one_base_post(_):
            t0 = time.time()
            http_json("POST", API + "/baseline/request", body)
            return round((time.time() - t0) * 1000.0, 3)

        seq = []
        for _ in range(seq_n):
            seq.append(one_base_post(None))
        with ThreadPoolExecutor(max_workers=conc_workers) as ex:
            conc = list(ex.map(one_base_post, range(conc_total)))
        label = "Baseline controller (/baseline/request)"

    out = {"sequential": seq, "concurrent": conc, "label": label}
    avg = sum(seq) / len(seq)
    p95 = sorted(seq)[int(len(seq) * 0.95)]
    cavg = sum(conc) / len(conc)
    print("  %-9s seq avg=%.3f ms p95=%.3f ms   conc avg=%.3f ms" %
          (kind, avg, p95, cavg))
    return out


# ------------------------------------------------------------------
# B3: trust score evolution trace
# ------------------------------------------------------------------
def bench_trust_trace():
    banner("B3: TRUST SCORE EVOLUTION TRACE")
    trace = []
    apps = [("legitimate_monitor", "monitor", 10),
            ("legitimate_admin", "admin", 10),
            ("compromised_app", "flood", 25)]
    for app_id, kind, reqs in apps:
        client = ZTClient(app_id)
        seq = 0
        for i in range(reqs):
            if kind == "flood":
                client._make_request("read", "flow_table",
                                     "install_flow", None, 2)
            elif kind == "monitor":
                if i % 5 == 4:
                    client._make_request("write", "flow_table",
                                         "install_flow", None, 2)
                else:
                    client._make_request("read", "flow_stats",
                                         "install_flow", None, 1)
            else:
                client._make_request("read" if i % 5 != 4 else "write",
                                     "flow_table", "install_flow", None, 1)
            seq += 1
            _, stats = http_json("GET", API + "/zt/stats")
            trace.append({
                "app": app_id, "request": seq,
                "trust_score": stats["trust_scores"].get(app_id, 0.0),
                "elapsed": seq
            })
            if kind != "flood":
                time.sleep(0.5)
    with open(os.path.join(RESULTS, "b3_trust_trace.csv"), "w",
              newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["app", "request",
                                               "trust_score", "elapsed"])
        writer.writeheader()
        writer.writerows(trace)
    for app_id in ("legitimate_monitor", "legitimate_admin",
                   "compromised_app"):
        pts = [t for t in trace if t["app"] == app_id]
        print("  %-19s start=%.2f end=%.2f" %
              (app_id, pts[0]["trust_score"], pts[-1]["trust_score"]))
    return trace


# ------------------------------------------------------------------
# Plots (matplotlib, if available)
# ------------------------------------------------------------------
def make_plots(b1, b2, trace):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("  matplotlib not available - skipping figures")
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    for app_id in ("legitimate_monitor", "legitimate_admin",
                   "compromised_app"):
        pts = [t for t in trace if t["app"] == app_id]
        ax.plot([t["request"] for t in pts],
                [t["trust_score"] for t in pts],
                marker="o", markersize=3, label=app_id)
    ax.set_xlabel("Request sequence number")
    ax.set_ylabel("Composite trust score")
    ax.set_title("Trust Score Evolution under Zero Trust")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "fig_trust.png"), dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(8, 5))
    for key in ("zt", "baseline"):
        samples = sorted(b2[key]["sequential"])
        n = len(samples)
        ax.plot(samples, [(i + 1) / n for i in range(n)],
                label=b2[key]["label"])
    ax.set_xlabel("Latency (ms)")
    ax.set_ylabel("CDF")
    ax.set_title("Northbound Request Latency CDF")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "fig_latency.png"), dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(8, 5))
    names = list(b1["attacks"].keys())
    rates = [b1["attacks"][k]["detection_rate"] for k in names]
    bars = ax.bar(names, rates, color="steelblue")
    ax.set_ylabel("Detection rate")
    ax.set_ylim(0, 1.1)
    ax.set_title("Zero Trust Detection Rate per Threat Class (50 runs)")
    ax.bar_label(bars, fmt="%.2f")
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "fig_detection.png"), dpi=150)
    plt.close(fig)
    print("  figures written")


# ------------------------------------------------------------------
def clean_environment():
    subprocess.run("echo tanis123 | sudo -S pkill -9 -x ryu-manager",
                   shell=True, capture_output=True)
    time.sleep(2)
    subprocess.run("echo tanis123 | sudo -S mn -c",
                   shell=True, capture_output=True)
    time.sleep(2)


def main():
    banner("PHASE 0: PYTHON DEPS CHECK + ENVIRONMENT CLEANUP")
    clean_environment()
    try:
        import matplotlib  # noqa: F401
        print("  matplotlib OK")
    except ImportError:
        print("  installing matplotlib ...")
        subprocess.run([sys.executable, "-m", "pip", "install",
                        "--user", "--quiet", "matplotlib"])

    banner("PHASE 1: START ZERO TRUST CONTROLLER + TOPOLOGY")
    zt_proc = start_controller("ryu_controller.py")
    net = start_topology()
    time.sleep(2)

    b3 = bench_trust_trace()
    b1 = bench_detection()

    stop_all(net, [zt_proc])
    clean_environment()

    banner("PHASE 2: BASELINE CONTROLLER (control group)")
    base_proc = start_controller("baseline_controller.py")
    net2 = start_topology()
    time.sleep(2)
    b2 = {"baseline": bench_latency("baseline")}
    stop_all(net2, [base_proc])
    clean_environment()

    banner("PHASE 3: ZERO TRUST CONTROLLER LATENCY")
    zt_proc2 = start_controller("ryu_controller.py")
    net3 = start_topology()
    time.sleep(2)
    b2["zt"] = bench_latency("zt")
    stop_all(net3, [zt_proc2])
    json.dump(b2, open(os.path.join(RESULTS, "b2_latency.json"), "w"))

    make_plots(b1, b2, b3)
    print("\nALL BENCHES COMPLETE - results in %s" % RESULTS)


if __name__ == "__main__":
    main()
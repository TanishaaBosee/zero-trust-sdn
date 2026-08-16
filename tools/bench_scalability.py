#!/usr/bin/env python3
"""
bench_scalability.py - scalability of the Zero Trust pipeline.
Run with sudo:  sudo python3 bench_scalability.py

For switch sizes 4 / 8 / 16 hosts:
  - connectivity: full ping matrix loss %
  - sequential northbound latency (200 samples): avg / p95 / max
  - concurrent load (50 requests, 10 workers): avg
Writes /home/tanis/bench_results/b4_scalability.json + fig_scalability.png
"""
import os
import sys
import time
import json
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor

PROJECT = "/home/tanis/zero-trust-sdn"
CONTROLLER_DIR = os.path.join(PROJECT, "controller")
RESULTS = "/home/tanis/bench_results"
API = "http://127.0.0.1:8080"

sys.path.insert(0, os.path.join(PROJECT, "apps"))
from http_app_client import ZTClient  # noqa: E402

os.makedirs(RESULTS, exist_ok=True)


def banner(t):
    print("\n" + "=" * 62)
    print("  " + t)
    print("=" * 62, flush=True)


def wait_api(url, seconds=60):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                return json.load(r)
        except Exception:
            time.sleep(2)
    return None


def clean():
    subprocess.run("echo tanis123 | sudo -S pkill -9 -x ryu-manager",
                   shell=True, capture_output=True)
    time.sleep(2)
    subprocess.run("echo tanis123 | sudo -S mn -c",
                   shell=True, capture_output=True)
    time.sleep(2)


def start_controller():
    proc = subprocess.Popen(
        ["ryu-manager", "ryu_controller.py"],
        cwd=CONTROLLER_DIR,
        stdout=open("/tmp/bench_scal.log", "w"),
        stderr=subprocess.STDOUT)
    if wait_api(API + "/zt/stats") is None:
        raise RuntimeError("controller did not come up")
    return proc


def start_topology(n_hosts):
    sys.path.insert(0, os.path.join(PROJECT, "topology"))
    from mininet.topo import Topo
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController

    class StarTopo(Topo):
        def __init__(self, n):
            Topo.__init__(self)
            s = self.addSwitch("s1")
            for i in range(1, n + 1):
                h = self.addHost("h%d" % i)
                self.addLink(h, s)

    net = Mininet(topo=StarTopo(n_hosts),
                  controller=lambda name: RemoteController(
                      name, ip="127.0.0.1", port=6653),
                  switch=OVSSwitch, build=True, autoSetMacs=True)
    net.start()
    time.sleep(4)
    return net


def bench_size(n_hosts, net):
    banner("SCALABILITY: %d hosts" % n_hosts)
    failures = net.ping(timeout=2)
    n_hosts_total = len(net.hosts)
    total_pings = n_hosts_total * (n_hosts_total - 1)
    loss = (100.0 * failures / total_pings if total_pings else 0.0)

    client = ZTClient("legitimate_monitor")
    seq_avg = p95 = mx = 0.0
    samples = []
    for _ in range(200):
        t0 = time.time()
        client._make_request("read", "flow_stats", "install_flow", None, 1)
        samples.append((time.time() - t0) * 1000.0)
    seq_avg = sum(samples) / len(samples)
    samples.sort()
    p95 = samples[int(len(samples) * 0.95)]
    mx = samples[-1]

    def one(_):
        t0 = time.time()
        client._make_request("read", "flow_stats", "install_flow", None, 1)
        return (time.time() - t0) * 1000.0

    with ThreadPoolExecutor(max_workers=10) as ex:
        conc = list(ex.map(one, range(50)))
    conc_avg = sum(conc) / len(conc)

    stats = wait_api(API + "/zt/stats")
    row = {
        "hosts": n_hosts,
        "ping_loss_pct": loss,
        "seq_avg_ms": round(seq_avg, 3),
        "seq_p95_ms": round(p95, 3),
        "seq_max_ms": round(mx, 3),
        "conc_avg_ms": round(conc_avg, 3),
        "connected_switches": stats.get("connected_switches", [])
    }
    print("  %2d hosts | ping_loss=%s | seq avg=%.3f p95=%.3f max=%.3f | conc avg=%.3f" %
          (n_hosts, loss, seq_avg, p95, mx, conc_avg))
    return row


def plot(results):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("  matplotlib missing - skipping figure")
        return
    hosts = [r["hosts"] for r in results]
    avg = [r["seq_avg_ms"] for r in results]
    p95 = [r["seq_p95_ms"] for r in results]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(hosts, avg, marker="o", linestyle="-", label="avg")
    ax.plot(hosts, p95, marker="s", linestyle="--", label="p95 (seq)")
    ax.set_xlabel("Network size (hosts, single OVS switch)")
    ax.set_ylabel("Northbound request latency (ms)")
    ax.set_title("Zero Trust Pipeline Scalability")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "fig_scalability.png"), dpi=150)
    plt.close(fig)
    print("  figure written")


def main():
    banner("SCALABILITY BENCH")
    clean()
    results = []
    for size in (4, 8, 16):
        zt_proc = start_controller()
        net = start_topology(size)
        time.sleep(2)
        results.append(bench_size(size, net))
        net.stop()
        zt_proc.terminate()
        clean()

    json.dump(results, open(os.path.join(RESULTS, "b4_scalability.json"), "w"),
              indent=1)
    plot(results)
    print("\nSCALABILITY COMPLETE -> %s/b4_scalability.json" % RESULTS)


if __name__ == "__main__":
    main()
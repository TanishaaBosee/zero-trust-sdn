"""
test_performance.py - Performance Measurement Framework
=========================================================
This script measures the overhead of the Zero Trust verification
pipeline in isolation (no Mininet needed - pure Python), plus gives
the exact commands to measure network-level metrics in Mininet.

Metrics measured here:
  1. Authentication Delay        - time for one-time registration+token
  2. Trust Verification Latency  - time of verify_request() per request
  3. Throughput (requests/sec)   - how many verified requests per second
  4. Network Overhead            - payload bytes of one ZT request
  5. Controller Response Time    - simulated end-to-end response time
  6. CPU / Memory usage          - via psutil if available

Metrics measured in Mininet (run the commands printed at the end):
  7. Throughput (Mbps)           - iperf3 between hosts, with iperf
  8. Packet loss                 - iperf3 reports lost packets
  9. Switch flow count           - ovs-ofctl dump-flows

Run:  python3 tests/test_performance.py
"""

import sys
import os
import time
import json
import statistics

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controller.trust_verification import TrustVerificationEngine

# optionally measure real CPU/memory usage of this process
try:
    import psutil
    _HAVE_PSUTIL = True
except ImportError:
    _HAVE_PSUTIL = False


class PerformanceMeasurement:
    """Measures the performance metrics of the Zero Trust pipeline."""

    def __init__(self):
        self.results = {}
        self.trust_engine = TrustVerificationEngine()
        self.trust_engine.register_application(
            "legitimate_monitor",
            "monitor_api_key_2024_secure",
            "monitoring_app",
            {"device_id": "device-001",
             "device_fingerprint": "fp_monitor_device_001"})

    def _valid_request(self):
        """Build a fully valid request (used in every measurement)."""
        token_data = self.trust_engine.generate_token("legitimate_monitor")
        return {
            "app_id": "legitimate_monitor",
            "action": "read",
            "resource": "flow_stats",
            "token": token_data["token"],
            "api_key": "monitor_api_key_2024_secure",
            "device_id": "device-001",
            "device_fingerprint": "fp_monitor_device_001",
            "role": "monitoring_app",
            "timestamp": int(time.time())
        }

    # ------------------------------------------------------------------
    # 1) Authentication delay: one-time registration cost
    # ------------------------------------------------------------------
    def measure_authentication_delay(self):
        samples = []
        for i in range(50):
            t0 = time.time()
            self.trust_engine.register_application(
                f"perf_app_{i}", f"perf_key_{i}", "monitoring_app",
                {"device_id": f"device-p-{i}",
                 "device_fingerprint": f"fp_p_{i}"})
            samples.append((time.time() - t0) * 1000)   # ms
        self.results["auth_delay_ms"] = {
            "avg": round(statistics.mean(samples), 3),
            "min": round(min(samples), 3),
            "max": round(max(samples), 3),
            "n": len(samples)
        }

    # ------------------------------------------------------------------
    # 2) + 3) Verification latency and throughput
    # ------------------------------------------------------------------
    def measure_verification_latency(self):
        samples = []
        req = self._valid_request()
        t0 = time.time()
        for _ in range(200):
            s = time.time()
            self.trust_engine.verify_request("legitimate_monitor", req)
            samples.append((time.time() - s) * 1000)    # ms
        elapsed = time.time() - t0
        self.results["verify_latency_ms"] = {
            "avg": round(statistics.mean(samples), 3),
            "min": round(min(samples), 3),
            "max": round(max(samples), 3),
            "stdev": round(statistics.stdev(samples), 3)
        }
        self.results["throughput_req_per_sec"] = round(200 / elapsed, 1)

    # ------------------------------------------------------------------
    # 4) Network overhead: size of one verified request
    # ------------------------------------------------------------------
    def measure_network_overhead(self):
        payload = json.dumps(self._valid_request())
        self.results["zt_request_overhead_bytes"] = len(payload.encode("utf-8"))

    # ------------------------------------------------------------------
    # 5) Controller response time (pure-pipeline simulation)
    # ------------------------------------------------------------------
    def measure_response_time(self):
        req = self._valid_request()
        samples = []
        for _ in range(200):
            t0 = time.time()
            verdict = self.trust_engine.verify_request("legitimate_monitor",
                                                       req)
            samples.append((time.time() - t0) * 1000)
        self.results["controller_response_time_ms"] = {
            "avg": round(statistics.mean(samples), 3),
            "discarded_denied": self.results.get("denied_in_sample", "n/a")
        }

    # ------------------------------------------------------------------
    # 6) CPU / memory usage of the verification pipeline process
    # ------------------------------------------------------------------
    def measure_resource_usage(self):
        if not _HAVE_PSUTIL:
            self.results["cpu_mem"] = "psutil not installed - use `sudo " \
                "pip3 install psutil` for real measurements"
            return
        proc = psutil.Process()
        req = self._valid_request()
        # hammer the pipeline for ~3 seconds while sampling CPU
        cpu_samples = []
        end = time.time() + 3
        while time.time() < end:
            self.trust_engine.verify_request("legitimate_monitor", req)
            cpu_samples.append(proc.cpu_percent(interval=None))
        self.results["cpu_percent"] = round(
            sum(cpu_samples) / max(1, len(cpu_samples)), 1)
        self.results["memory_mb"] = round(proc.memory_info().rss / (1024**2), 1)

    def run_all(self):
        print("=" * 60)
        print("PERFORMANCE MEASUREMENT - ZERO TRUST PIPELINE")
        print("=" * 60)
        print("(1/6) Authentication delay ...")
        self.measure_authentication_delay()
        print("(2/6) Verification latency + throughput ...")
        self.measure_verification_latency()
        print("(3/6) Network overhead ...")
        self.measure_network_overhead()
        print("(4/6) Controller response time ...")
        self.measure_response_time()
        print("(5/6) Resource usage ...")
        self.measure_resource_usage()

        os.makedirs("results", exist_ok=True)
        out = f"results/perf_{int(time.time())}.json"
        with open(out, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\n[SAVED] results -> {out}")
        print(json.dumps(self.results, indent=2))

        print()
        print("NEXT: network-level measurements in Mininet")
        print("-" * 60)
        print("  iperf3 with baseline controller:")
        print("    sudo ryu-manager controller/basic_controller.py")
        print("    sudo python3 topology/network_topology.py")
        print("    mininet> h1 iperf3 -s &  (on h1)")
        print("    mininet> h4 iperf3 -c 10.0.0.1 -t 10")
        print("  then repeat with the Zero Trust controller and compare:")
        print("    sudo ryu-manager controller/ryu_controller.py")
        print("  switch flow count:")
        print("    sudo ovs-ofctl -O OpenFlow13 dump-flows s1")


if __name__ == "__main__":
    PerformanceMeasurement().run_all()
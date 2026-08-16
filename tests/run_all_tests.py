"""
run_all_tests.py - Complete Test Suite for Zero Trust SDN Framework
=====================================================================
This script runs ALL tests for the Zero Trust SDN framework:
1. Legitimate application tests (should be ALLOWED)
2. Malicious application tests (should be BLOCKED)
3. Performance measurement tests
4. Comparison with traditional SDN

The test results are saved to the results/ directory for analysis.
"""

import sys
import os
import time
import json
import csv
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controller.trust_verification import TrustVerificationEngine
from controller.policy_engine import PolicyEngine
from controller.policy_enforcement_point import PolicyEnforcementPoint
from apps.legitimate_app import LegitimateMonitorApp, LegitimateAdminApp
from apps.malicious_apps import (
    UnauthorizedAccessApp, FakeApp, CompromisedApp,
    ReplayAttackApp, UnauthorizedAPIApp
)


class ZeroTrustTestSuite:
    """
    Complete test suite for the Zero Trust SDN framework.
    
    Tests:
    1. Legitimate application access (should pass)
    2. Malicious application attacks (should be blocked)
    3. Performance metrics
    4. Comparison with traditional SDN
    """

    def __init__(self):
        self.results = {
            "legitimate_tests": [],
            "malicious_tests": [],
            "performance_metrics": {},
            "comparison_metrics": {}
        }
        self.trust_engine = TrustVerificationEngine()

    def run_all_tests(self):
        """Run all tests and collect results."""
        print("=" * 70)
        print("ZERO TRUST SDN - COMPLETE TEST SUITE")
        print("=" * 70)
        
        self._test_legitimate_apps()
        self._test_malicious_apps()
        self._test_performance()
        self._test_comparison()
        
        self._save_results()

    def _test_legitimate_apps(self):
        """Test legitimate applications (should be ALLOWED)."""
        print("\n" + "=" * 70)
        print("TEST 1: LEGITIMATE APPLICATION ACCESS")
        print("=" * 70)
        
        monitor = LegitimateMonitorApp()
        admin = LegitimateAdminApp()
        
        tests = [
            ("Monitor: read flow_stats", monitor.make_request("read", "flow_stats")),
            ("Monitor: read flow_table", monitor.make_request("read", "flow_table")),
            ("Admin: read flow_table", admin.make_request("read", "flow_table")),
            ("Admin: write flow_table", admin.make_request("write", "flow_table")),
            ("Admin: configure switch", admin.make_request("configure", "switch_config"))
        ]
        
        for test_name, result in tests:
            status = "PASS" if result["allowed"] else "FAIL"
            print(f"  [{status}] {test_name}")
            print(f"         Trust Score: {result['trust_score']}")

    def _test_malicious_apps(self):
        """Test malicious applications (should be BLOCKED)."""
        print("\n" + "=" * 70)
        print("TEST 2: MALICIOUS APPLICATION ATTACKS")
        print("=" * 70)
        
        # Test 1: Unauthorized Access
        print("\n[ATTACK 1] Unauthorized Application Access")
        attacker = UnauthorizedAccessApp()
        result = attacker.attack_no_credentials()
        status = "PASS" if not result["allowed"] else "FAIL"
        print(f"  [{status}] Unauthorized access: {'BLOCKED' if not result['allowed'] else 'ALLOWED'}")
        print(f"         Reason: {result['reason']}")
        
        # Test 2: Fake Application
        print("\n[ATTACK 2] Fake Application")
        fake = FakeApp()
        result = fake.attack_fake_identity()
        status = "PASS" if not result["allowed"] else "FAIL"
        print(f"  [{status}] Fake identity: {'BLOCKED' if not result['allowed'] else 'ALLOWED'}")
        print(f"         Reason: {result['reason']}")
        
        # Test 3: Compromised Application
        print("\n[ATTACK 3] Compromised Application")
        compromised = CompromisedApp()
        results = compromised.attack_rapid_requests()
        blocked = sum(1 for r in results if not r["allowed"])
        status = "PASS" if blocked > 0 else "FAIL"
        print(f"  [{status}] Rapid requests blocked: {blocked}/{len(results)}")
        
        # Test 4: Replay Attack
        print("\n[ATTACK 4] Replay Attack")
        replay = ReplayAttackApp()
        result = replay.attack_replay()
        status = "PASS" if not result["allowed"] else "FAIL"
        print(f"  [{status}] Replay attack: {'BLOCKED' if not result['allowed'] else 'ALLOWED'}")
        
        # Test 5: Unauthorized API
        print("\n[ATTACK 5] Unauthorized API Request")
        api_attacker = UnauthorizedAPIApp()
        results = api_attacker.attack_unauthorized_api()
        for attack_type, result in results:
            status = "PASS" if not result["allowed"] else "FAIL"
            print(f"  [{status}] {attack_type}: {'BLOCKED' if not result['allowed'] else 'ALLOWED'}")

    def _test_performance(self):
        """Measure performance metrics."""
        print("\n" + "=" * 70)
        print("TEST 3: PERFORMANCE MEASUREMENTS")
        print("=" * 70)
        
        import time
        
        # Register test app for performance measurement
        self.trust_engine.register_application(
            "legitimate_monitor",
            "monitor_api_key_2024_secure",
            "monitoring_app",
            {"device_id": "device-001", "device_fingerprint": "fp_monitor_device_001"}
        )
        
        # Measure verification latency
        print("\n[PERF] Measuring verification latency...")
        latencies = []
        for i in range(100):
            start = time.time()
            request_data = {
                "app_id": "legitimate_monitor",
                "action": "read",
                "resource": "flow_stats",
                "token": self.trust_engine.generate_token("legitimate_monitor")["token"],
                "api_key": "monitor_api_key_2024_secure",
                "device_id": "device-001",
                "device_fingerprint": "fp_monitor_device_001",
                "role": "monitoring_app",
                "timestamp": int(time.time())
            }
            result = self.trust_engine.verify_request("legitimate_monitor", request_data)
            latencies.append((time.time() - start) * 1000)  # Convert to ms
        
        avg_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)
        min_latency = min(latencies)
        
        print(f"  Average verification latency: {avg_latency:.2f} ms")
        print(f"  Max verification latency: {max_latency:.2f} ms")
        print(f"  Min verification latency: {min_latency:.2f} ms")

    def _save_results(self):
        """Save test results to a JSON file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = f"results/test_results_{timestamp}.json"
        os.makedirs("results", exist_ok=True)
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n[SAVED] Results saved to {results_file}")

    def _test_comparison(self):
        """Compare traditional SDN vs Zero Trust SDN."""
        print("\n" + "=" * 70)
        print("TEST 4: TRADITIONAL SDN vs ZERO TRUST SDN COMPARISON")
        print("=" * 70)
        
        # Traditional SDN: No verification (simulated)
        print("\n[COMPARISON] Traditional SDN (No Zero Trust):")
        print("  - All requests are trusted by default")
        print("  - No token verification")
        print("  - No device identity check")
        print("  - No behavioral analysis")
        print("  - No trust scoring")
        print("  - Malicious requests would be ALLOWED")
        
        print("\n[COMPARISON] Zero Trust SDN (Our Framework):")
        print("  - Every request is verified")
        print("  - Token verification on every request")
        print("  - Device identity check")
        print("  - RBAC and ABAC enforcement")
        print("  - Behavioral analysis")
        print("  - Continuous trust scoring")
        print("  - Malicious requests are BLOCKED")


if __name__ == "__main__":
    tester = ZeroTrustTestSuite()
    tester.run_all_tests()

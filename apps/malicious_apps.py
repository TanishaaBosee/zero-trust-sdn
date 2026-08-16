"""
malicious_apps.py - Malicious Applications for Zero Trust Testing
==================================================================
This script simulates DIFFERENT TYPES of malicious applications
that attempt to attack the SDN controller.

Attack Types:
1. Unauthorized Application Access - App without valid credentials
2. Fake Application - App pretending to be legitimate
3. Compromised Application - Legitimate app that has been compromised
4. Replay Attack - Reusing old valid tokens
5. Unauthorized API Request - Request without proper authorization

Each attack is detected and blocked by the Zero Trust framework.
"""

import sys
import os
import time
import json
import hashlib
import hmac
import random

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controller.trust_verification import TrustVerificationEngine


class MaliciousApp:
    """
    Base class for malicious applications used in testing.
    
    These applications attempt various attacks that should be
    detected and blocked by the Zero Trust framework.
    """

    def __init__(self, app_id, api_key, role, device_info):
        self.app_id = app_id
        self.api_key = api_key
        self.role = role
        self.device_info = device_info
        self.trust_engine = TrustVerificationEngine()
        self._register()

    def _register(self):
        """Register with the Zero Trust framework."""
        self.trust_engine.register_application(
            self.app_id, self.api_key, self.role, self.device_info
        )

    def send_request(self, request_data):
        """Send a request through the Zero Trust framework."""
        result = self.trust_engine.verify_request(self.app_id, request_data)
        return result


class UnauthorizedAccessApp(MaliciousApp):
    """
    Attack Type 1: Unauthorized Application Access
    
    This app tries to access the controller WITHOUT any credentials.
    It does not provide:
    - Valid token
    - API key
    - Device identity
    
    Expected: BLOCKED by Zero Trust framework
    """

    def __init__(self):
        super().__init__(
            app_id="malicious_attacker",
            api_key="malicious_key_2024",
            role="guest_app",
            device_info={
                "device_id": "device-mal-001",
                "device_fingerprint": "fp_malicious_001"
            }
        )

    def attack_no_credentials(self):
        """
        Attack: Request without any credentials.
        
        This simulates an attacker trying to access the controller
        without providing any authentication.
        """
        request_data = {
            "app_id": self.app_id,
            "action": "read",
            "resource": "flow_table",
            "token": "",  # No token
            "api_key": "",  # No API key
            "device_id": "",
            "device_fingerprint": "",
            "role": "guest_app",
            "timestamp": int(time.time())
        }
        return self.trust_engine.verify_request(self.app_id, request_data)


class FakeApp(MaliciousApp):
    """
    Attack Type 2: Fake Application
    
    This app pretends to be a legitimate monitoring application
    but uses stolen/fake credentials.
    
    Expected: BLOCKED by Zero Trust framework
    """

    def __init__(self):
        super().__init__(
            app_id="fake_app",
            api_key="fake_key_2024",
            role="monitoring_app",  # Pretending to be monitoring app
            device_info={
                "device_id": "device-fake-001",
                "device_fingerprint": "fp_fake_001"
            }
        )

    def attack_fake_identity(self):
        """
        Attack: Pretend to be a legitimate monitoring app.
        
        The fake app uses stolen credentials but the device
        identity and fingerprint don't match the registered device.
        """
        request_data = {
            "app_id": self.app_id,
            "action": "read",
            "resource": "flow_stats",
            "token": self.trust_engine.generate_token(self.app_id)["token"],
            "api_key": self.api_key,
            "device_id": "device-001",  # Pretending to be legitimate device
            "device_fingerprint": "wrong_fingerprint",  # Wrong fingerprint!
            "role": "monitoring_app",
            "timestamp": int(time.time())
        }
        return self.trust_engine.verify_request(self.app_id, request_data)


class CompromisedApp(MaliciousApp):
    """
    Attack Type 3: Compromised Application
    
    A legitimate application that has been compromised by an attacker.
    It has valid credentials but exhibits anomalous behavior.
    
    Expected: BLOCKED by behavioral analysis
    """

    def __init__(self):
        super().__init__(
            app_id="compromised_app",
            api_key="compromised_key_2024",
            role="monitoring_app",
            device_info={
                "device_id": "device-comp-001",
                "device_fingerprint": "fp_compromised_001"
            }
        )

    def attack_rapid_requests(self):
        """
        Attack: Make rapid requests to simulate a compromised app.
        
        A compromised app might try to:
        - Flood the controller with requests
        - Access resources it shouldn't
        - Make unauthorized changes
        """
        results = []
        for i in range(15):  # Make 15 rapid requests
            request_data = {
                "app_id": self.app_id,
                "action": "read",
                "resource": "flow_table",
                "token": self.trust_engine.generate_token(self.app_id)["token"],
                "api_key": self.api_key,
                "device_id": self.device_info.get("device_id"),
                "device_fingerprint": self.device_info.get("device_fingerprint"),
                "role": self.role,
                "timestamp": int(time.time())
            }
            result = self.trust_engine.verify_request(self.app_id, request_data)
            results.append(result)
        
        return results


class ReplayAttackApp(MaliciousApp):
    """
    Attack Type 4: Replay Attack
    
    This app captures a valid token and tries to reuse it later.
    
    Expected: BLOCKED by token expiry verification
    """

    def __init__(self):
        super().__init__(
            app_id="malicious_attacker",
            api_key="malicious_key_2024",
            role="guest_app",
            device_info={
                "device_id": "device-mal-001",
                "device_fingerprint": "fp_malicious_001"
            }
        )

    def attack_replay(self):
        """
        Attack: Reuse an old/stolen token.
        
        The attacker captures a valid token and tries to reuse it
        after it has expired.
        """
    def attack_replay(self):
        """
        Attack: Reuse an old/stolen token.
        
        The attacker captures a valid token and tries to reuse it
        after it has expired. We simulate the time delay without
        actually waiting 65 seconds.
        """
        # Get a valid token first
        token_data = self.trust_engine.generate_token(self.app_id)
        old_token = token_data["token"]
        old_timestamp = token_data["timestamp"] - 120  # Simulate 120 seconds old
        
        # Try to reuse the expired token
        request_data = {
            "app_id": self.app_id,
            "action": "read",
            "resource": "flow_table",
            "token": old_token,  # Expired token!
            "api_key": self.api_key,
            "device_id": self.device_info.get("device_id"),
            "device_fingerprint": self.device_info.get("device_fingerprint"),
            "role": self.role,
            "timestamp": old_timestamp  # Old timestamp!
        }
        
        return self.trust_engine.verify_request(self.app_id, request_data)


class UnauthorizedAPIApp(MaliciousApp):
    """
    Attack Type 5: Unauthorized API Request
    
    This app makes API requests without proper authorization.
    
    Expected: BLOCKED by RBAC/ABAC checks
    """

    def __init__(self):
        super().__init__(
            app_id="malicious_attacker",
            api_key="malicious_key_2024",
            role="guest_app",
            device_info={
                "device_id": "device-mal-001",
                "device_fingerprint": "fp_malicious_001"
            }
        )

    def attack_unauthorized_api(self):
        """
        Attack: Make API requests without proper authorization.
        
        The app tries to:
        - Delete flow entries (admin only)
        - Configure the controller (admin only)
        - Access sensitive resources
        """
        results = []
        
        # Attack 1: Try to delete flow entries
        request_data = {
            "app_id": self.app_id,
            "action": "delete",
            "resource": "flow_table",
            "token": self.trust_engine.generate_token(self.app_id)["token"],
            "api_key": self.api_key,
            "device_id": self.device_info.get("device_id"),
            "device_fingerprint": self.device_info.get("device_fingerprint"),
            "role": "guest_app",
            "timestamp": int(time.time())
        }
        results.append(("delete_flow", self.trust_engine.verify_request(self.app_id, request_data)))
        
        # Attack 2: Try to configure controller
        request_data["action"] = "configure"
        request_data["resource"] = "controller_config"
        results.append(("configure_controller", self.trust_engine.verify_request(self.app_id, request_data)))
        
        return results


if __name__ == "__main__":
    print("=" * 60)
    print("Zero Trust SDN - Malicious Application Attack Simulation")
    print("=" * 60)
    
    # Test 1: Unauthorized Access
    print("\n[ATTACK 1] Unauthorized Application Access")
    attacker = UnauthorizedAccessApp()
    result = attacker.attack_no_credentials()
    print(f"  Result: {'BLOCKED' if not result['allowed'] else 'ALLOWED'}")
    print(f"  Reason: {result['reason']}")
    print(f"  Trust Score: {result['trust_score']}")
    
    # Test 2: Fake Application
    print("\n[ATTACK 2] Fake Application")
    fake = FakeApp()
    result = fake.attack_fake_identity()
    print(f"  Result: {'BLOCKED' if not result['allowed'] else 'ALLOWED'}")
    print(f"  Reason: {result['reason']}")
    print(f"  Trust Score: {result['trust_score']}")
    
    # Test 3: Compromised Application
    print("\n[ATTACK 3] Compromised Application (Rapid Requests)")
    compromised = CompromisedApp()
    results = compromised.attack_rapid_requests()
    allowed = sum(1 for r in results if r["allowed"])
    blocked = sum(1 for r in results if not r["allowed"])
    print(f"  Allowed: {allowed}, Blocked: {blocked}")
    print(f"  Last request reason: {results[-1]['reason']}")
    
    # Test 4: Replay Attack
    print("\n[ATTACK 4] Replay Attack")
    replay = ReplayAttackApp()
    result = replay.attack_replay()
    print(f"  Result: {'BLOCKED' if not result['allowed'] else 'ALLOWED'}")
    print(f"  Reason: {result['reason']}")
    
    # Test 5: Unauthorized API Request
    print("\n[ATTACK 5] Unauthorized API Request")
    api_attacker = UnauthorizedAPIApp()
    results = api_attacker.attack_unauthorized_api()
    for attack_type, result in results:
        print(f"  {attack_type}: {'BLOCKED' if not result['allowed'] else 'ALLOWED'}")
        print(f"    Reason: {result['reason']}")

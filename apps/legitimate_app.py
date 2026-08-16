"""
legitimate_app.py - Legitimate Application for Zero Trust Testing
==================================================================
This script simulates a LEGITIMATE application that:
1. Registers with the Zero Trust framework
2. Obtains valid credentials (token, API key)
3. Makes legitimate requests to the SDN controller
4. Follows all security protocols

This application SHOULD be allowed by the Zero Trust framework.
"""

import sys
import os
import time
import json
import hashlib
import hmac
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controller.trust_verification import TrustVerificationEngine


class LegitimateApp:
    """
    Legitimate Application for Zero Trust Testing
    
    This application:
    1. Registers with the Zero Trust framework
    2. Obtains valid credentials
    3. Makes legitimate requests
    4. Follows all security protocols
    
    Expected behavior: ALL requests should be ALLOWED
    """

    def __init__(self, app_id, api_key, role, device_info):
        self.app_id = app_id
        self.api_key = api_key
        self.role = role
        self.device_info = device_info
        self.token = None
        self.token_timestamp = None
        self.trust_engine = TrustVerificationEngine()
        
        # Register with Zero Trust framework
        self._register()

    def _register(self):
        """Register with the Zero Trust framework."""
        result = self.trust_engine.register_application(
            self.app_id, self.api_key, self.role, self.device_info
        )
        print(f"[{self.app_id}] Registered: {result['status']}")
        
        # Get initial token
        token_data = self.trust_engine.generate_token(self.app_id)
        self.token = token_data["token"]
        self.token_timestamp = token_data["timestamp"]

    def make_request(self, action, resource):
        """
        Make a legitimate request to the SDN controller.
        
        Every request includes:
        - Valid token (refreshed if expired)
        - Valid API key
        - Device identity
        - Role information
        
        Returns the verification result directly.
        """
        # Refresh token if expired (tokens valid for 60 seconds)
        if time.time() - self.token_timestamp > 55:
            token_data = self.trust_engine.generate_token(self.app_id)
            self.token = token_data["token"]
            self.token_timestamp = token_data["timestamp"]
        
        request_data = {
            "app_id": self.app_id,
            "action": action,
            "resource": resource,
            "token": self.token,
            "api_key": self.api_key,
            "device_id": self.device_info.get("device_id"),
            "device_fingerprint": self.device_info.get("device_fingerprint"),
            "role": self.role,
            "timestamp": int(time.time())
        }
        
        result = self.trust_engine.verify_request(self.app_id, request_data)
        return result


class LegitimateMonitorApp(LegitimateApp):
    """Legitimate Network Monitoring Application."""
    
    def __init__(self):
        super().__init__(
            app_id="legitimate_monitor",
            api_key="monitor_api_key_2024_secure",
            role="monitoring_app",
            device_info={
                "device_id": "device-001",
                "device_fingerprint": "fp_monitor_device_001",
                "hostname": "h1",
                "mac_address": "00:00:00:00:00:01"
            }
        )


class LegitimateAdminApp(LegitimateApp):
    """Legitimate Network Administration Application."""
    
    def __init__(self):
        super().__init__(
            app_id="legitimate_admin",
            api_key="admin_api_key_2024_secure",
            role="admin",
            device_info={
                "device_id": "device-002",
                "device_fingerprint": "fp_admin_device_002",
                "hostname": "h2",
                "mac_address": "00:00:00:00:00:02"
            }
        )


if __name__ == "__main__":
    print("=" * 60)
    print("Zero Trust SDN - Legitimate Application Test")
    print("=" * 60)
    
    # Test legitimate monitoring app
    monitor = LegitimateMonitorApp()
    print(f"\n[TEST] Legitimate Monitor App making requests...")
    
    # Test 1: Read flow stats (should be ALLOWED)
    result = monitor.make_request("read", "flow_stats")
    print(f"Request 1 (read flow_stats): {'ALLOWED' if result['allowed'] else 'DENIED'}")
    print(f"  Trust Score: {result['trust_score']}")
    print(f"  Reason: {result['reason']}")
    
    # Test 2: Read flow table (should be ALLOWED)
    result = monitor.make_request("read", "flow_table")
    print(f"Request 2 (read flow_table): {'ALLOWED' if result['allowed'] else 'DENIED'}")
    print(f"  Trust Score: {result['trust_score']}")
    
    # Test 3: Write to flow table (should be DENIED - monitoring app can't write)
    result = monitor.make_request("write", "flow_table")
    print(f"Request 3 (write flow_table): {'ALLOWED' if result['allowed'] else 'DENIED'}")
    print(f"  Trust Score: {result['trust_score']}")
    
    # Test legitimate admin app
    print("\n[TEST] Legitimate Admin App making requests...")
    admin = LegitimateAdminApp()
    
    # Test 4: Admin read (should be ALLOWED)
    result = admin.make_request("read", "flow_table")
    print(f"Request 4 (admin read flow_table): {'ALLOWED' if result['allowed'] else 'DENIED'}")
    
    # Test 5: Admin configure (should be ALLOWED)
    result = admin.make_request("configure", "switch_config")
    print(f"Request 5 (admin configure switch): {'ALLOWED' if result['allowed'] else 'DENIED'}")

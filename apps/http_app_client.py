#!/usr/bin/env python3
"""
http_app_client.py - Northbound HTTP Clients for the Zero Trust SDN Demo
=========================================================================
These clients run INSIDE Mininet hosts (or in the VM) and communicate
with the Zero Trust RYU controller over HTTP (northbound interface).

All requests MUST go through:  POST http://127.0.0.1:8080/zt/request
The controller's Zero Trust pipeline decides allow (200) / deny (403).

Usage examples:
  # legitimate applications (expect ALLOWED)
  python3 apps/http_app_client.py --app monitor
  python3 apps/http_app_client.py --app admin

  # malicious / attack applications (expect BLOCKED)
  python3 apps/http_app_client.py --attack no_credentials
  python3 apps/http_app_client.py --attack fake
  python3 apps/http_app_client.py --attack replay
  python3 apps/http_app_client.py --attack unauthorized
  python3 apps/http_app_client.py --attack flood
"""

import sys
import os
import json
import time
import argparse
import requests

# ----------------------------------------------------------------------
# Registered credentials of the demo applications (mirror config/trusted_apps.json)
# ----------------------------------------------------------------------
APP_REGISTRY = {
    # app_id -> (api_key, role, device_id, device_fingerprint, hostname)
    "legitimate_monitor": ("monitor_api_key_2024_secure", "monitoring_app",
                           "device-001", "fp_monitor_device_001", "h1"),
    "legitimate_admin":   ("admin_api_key_2024_secure", "admin",
                           "device-002", "fp_admin_device_002", "h2"),
    "malicious_attacker": ("malicious_key_2024", "guest_app",
                           "device-mal-001", "fp_malicious_001", "h3"),
    "fake_app":           ("fake_key_2024", "guest_app",
                           "device-fake-001", "fp_fake_001", "h3"),
    "compromised_app":    ("compromised_key_2024", "monitoring_app",
                           "device-comp-001", "fp_compromised_001", "h3"),
}

BASE_URL = "http://127.0.0.1:8080"


class ZTClient:
    """Base HTTP client that talks to the Zero Trust REST API."""

    def __init__(self, app_id, base_url=BASE_URL):
        self.app_id = app_id
        self.base_url = base_url
        api_key, role, dev_id, fp, host = APP_REGISTRY[app_id]
        self.api_key = api_key
        self.role = role
        self.device_id = dev_id
        self.fingerprint = fp
        self.hostname = host
        self.token = None
        self.token_timestamp = None
        self._register()

    # ------------------------------------------------------------------
    # Step 1 of the protocol: ONE-TIME registration.
    # The controller generates and returns a short-lived HMAC token.
    # ------------------------------------------------------------------
    def _register(self):
        body = {
            "app_id": self.app_id,
            "api_key": self.api_key,
            "role": self.role,
            "device_id": self.device_id,
            "device_fingerprint": self.fingerprint,
            "hostname": self.hostname,
        }
        r = requests.post(f"{self.base_url}/zt/register", json=body)
        data = r.json()
        self.token = data.get("token")
        self.token_timestamp = data.get("timestamp")
        print(f"[REGISTER] {self.app_id} -> HTTP {r.status_code} "
              f"{data.get('status')} token_expires_in={data.get('expires_in')}s")

    # ------------------------------------------------------------------
    # Step 2 (REPEATED for EVERY request): build a verified request.
    # Every request carries: token, timestamp, api_key, device identity,
    # role and the desired action - the controller re-verifies ALL of it.
    # ------------------------------------------------------------------
    def _make_request(self, action, resource, op="install_flow",
                      match=None, out_port=2, token_override=None,
                      timestamp_override=None, role_override=None,
                      device_id_override=None,
                      fingerprint_override=None):
        if timestamp_override is None:
            timestamp_override = (self.token_timestamp
                                  or int(time.time()))
        body = {
            "app_id": self.app_id,
            "action": action,               # read | write | delete | configure
            "resource": resource,           # flow_table | switch_config | ...
            "op": op,                       # install_flow | drop_flow
            "match": match or {},
            "out_port": out_port,
            "token": token_override if token_override is not None
                     else (self.token or ""),
            "timestamp": timestamp_override,
            "api_key": self.api_key,
            "device_id": (device_id_override if device_id_override is not None
                          else self.device_id),
            "device_fingerprint": (fingerprint_override
                                   if fingerprint_override is not None
                                   else self.fingerprint),
            "role": role_override or self.role,
        }
        r = requests.post(f"{self.base_url}/zt/request", json=body)
        return r.status_code, r.json()


# ----------------------------------------------------------------------
# LEGITIMATE DEMONSTRATION
# ----------------------------------------------------------------------
def run_legit(app_id):
    c = ZTClient(app_id)
    tests = [
        ("read flow_stats",       "read",     "flow_stats",
         "install_flow", None, 2),
        ("read flow_table",       "read",     "flow_table",
         "install_flow", None, 2),
        ("write flow_table",      "write",    "flow_table",
         "install_flow", {"eth_dst": "00:00:00:00:00:02"}, 2),
    ]
    for name, act, res, op, m, port in tests:
        code, data = c._make_request(act, res, op, m, port)
        verdict = "ALLOWED" if code == 200 else "DENIED"
        print(f"[{verdict}] {c.app_id}: {name} "
              f"(HTTP {code}, trust={data.get('trust_score')}, "
              f"reason={data.get('reason')})")


# ----------------------------------------------------------------------
# ATTACK 1: no credentials at all
# ----------------------------------------------------------------------
def run_no_credentials():
    c = ZTClient("malicious_attacker")
    # strip the token: build the request manually without token part
    body = {
        "app_id": c.app_id, "action": "read", "resource": "flow_table",
        "op": "install_flow", "match": {}, "out_port": 2,
        "token": "", "timestamp": int(time.time()),
        "api_key": c.api_key, "device_id": c.device_id,
        "device_fingerprint": c.fingerprint, "role": c.role,
    }
    r = requests.post(f"{BASE_URL}/zt/request", json=body)
    d = r.json()
    print(f"[{'DENIED' if r.status_code == 403 else 'ALLOWED'}] "
          f"no_credentials: HTTP {r.status_code} -> {d.get('reason')}")


# ----------------------------------------------------------------------
# ATTACK 2: fake identity (steals a legitimate device ID but carries
# the wrong device fingerprint -> device verification must catch it)
# ----------------------------------------------------------------------
def run_fake():
    c = ZTClient("fake_app")
    code, data = c._make_request(
        "read", "flow_stats", "install_flow", None, 2,
        role_override="monitoring_app",          # pretends to be a monitor
        device_id_override="device-001",         # stolen device ID
        fingerprint_override=c.fingerprint)      # its own (mismatching) fp
    print(f"[{'DENIED' if code == 403 else 'ALLOWED'}] fake: HTTP {code} -> "
          f"{data.get('reason')}")


# ----------------------------------------------------------------------
# ATTACK 3: replay attack (captured token replayed much later)
# ----------------------------------------------------------------------
def run_replay():
    c = ZTClient("malicious_attacker")
    # capture a token the attacker obtained earlier ...
    old_token = c.token
    old_ts = c.token_timestamp
    # ... and replay it claiming an OLD timestamp (token was captured
    # 2 minutes ago, outside the 60 s validity window)
    code, data = c._make_request("read", "flow_table", "install_flow",
                                 None, 2,
                                 token_override=old_token,
                                 timestamp_override=old_ts - 120)
    print(f"[{'DENIED' if code == 403 else 'ALLOWED'}] replay: HTTP {code} -> "
          f"{data.get('reason')}")


# ----------------------------------------------------------------------
# ATTACK 4: unauthorized API request (guest tries admin-only actions)
# ----------------------------------------------------------------------
def run_unauthorized():
    c = ZTClient("malicious_attacker")  # role = guest_app
    for name, act, res in [("delete_flow", "delete", "flow_table"),
                           ("configure_controller", "configure",
                            "controller_config")]:
        code, data = c._make_request(act, res, "install_flow", None, 2)
        print(f"[{'DENIED' if code == 403 else 'ALLOWED'}] {name}: "
              f"HTTP {code} -> {data.get('reason')}")


# ----------------------------------------------------------------------
# ATTACK 5: compromised app (valid credentials + abnormal behaviour:
# request flooding -> behavioral analysis blocks it)
# ----------------------------------------------------------------------
def run_flood():
    c = ZTClient("compromised_app")
    results = []
    for i in range(15):          # 15 rapid requests in a few seconds
        code, data = c._make_request("read", "flow_table", "install_flow",
                                     None, 2)
        results.append((code, data))
    allowed = sum(1 for code, _ in results if code == 200)
    denied = sum(1 for code, _ in results if code == 403)
    print(f"[flood] compromised_app: {allowed} ALLOWED, {denied} DENIED "
          f"(behavioral anomaly expected to block late requests)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZT SDN northbound client")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--app", choices=["monitor", "admin"],
                       help="run a legitimate application")
    group.add_argument("--attack",
                       choices=["no_credentials", "fake", "replay",
                                "unauthorized", "flood"],
                       help="run an attack simulation")
    args = parser.parse_args()

    if args.app == "monitor":
        run_legit("legitimate_monitor")
    elif args.app == "admin":
        run_legit("legitimate_admin")
    elif args.attack == "no_credentials":
        run_no_credentials()
    elif args.attack == "fake":
        run_fake()
    elif args.attack == "replay":
        run_replay()
    elif args.attack == "unauthorized":
        run_unauthorized()
    elif args.attack == "flood":
        run_flood()
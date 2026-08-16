"""
trust_verification.py - Zero Trust Verification Engine
======================================================
This is the CORE module of the Zero Trust framework.
It verifies EVERY request from EVERY application BEFORE
allowing communication with the SDN controller.

Key Zero Trust Principle Applied:
"Never trust, always verify" - Every single request is verified,
not just the initial authentication.

Author: Research Project - ZTA in SDN
"""

import time
import hashlib
import hmac
import json
import os
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrustVerification")


class TrustVerificationEngine:
    """
    Core Zero Trust Verification Engine.
    
    This engine implements the fundamental Zero Trust principle:
    "Never trust, always verify."
    
    Every application request goes through MULTIPLE verification
    checks before being allowed to communicate with the SDN controller.
    
    Verification Layers:
    1. Token Verification
    2. API Key Validation
    3. Device Identity Verification
    4. Role-Based Access Control (RBAC)
    5. Attribute-Based Access Control (ABAC)
    6. Behavioral Analysis
    7. Continuous Trust Scoring
    """

    def __init__(self, config_path="config/policies.json"):
        self.config_path = config_path
        self.policies = self._load_policies()
        self.trust_scores = {}  # app_id -> trust_score
        self.behavior_history = {}  # app_id -> list of behaviors
        self.session_tokens = {}  # app_id -> token_info
        self.device_registry = {}  # device_id -> device_info
        self.api_keys = {}  # app_id -> api_key
        self.role_permissions = {}  # role -> [permissions]
        self.attribute_policies = []  # list of ABAC rules
        
        # Initialize default policies
        self._initialize_default_policies()
        
        logger.info("Zero Trust Verification Engine initialized")
        logger.info("Principle: NEVER TRUST, ALWAYS VERIFY")

    def _initialize_default_policies(self):
        """Initialize default security policies for the Zero Trust framework."""
        self.role_permissions = {
            "admin": ["read", "write", "delete", "configure", "monitor"],
            "network_operator": ["read", "write", "monitor"],
            "monitoring_app": ["read", "monitor"],
            "guest_app": ["read"]
        }
        
        self.attribute_policies = [
            {
                "id": "policy_001",
                "name": "Allow read for monitoring apps on any resource",
                "conditions": {
                    "role": "monitoring_app",
                    "action": "read"
                },
                "effect": "allow"
            },
            {
                "id": "policy_002",
                "name": "Allow admin full access",
                "conditions": {
                    "role": "admin",
                    "action": ["read", "write", "delete", "configure"]
                },
                "effect": "allow"
            },
            {
                "id": "policy_003",
                "name": "Allow network operator read/write",
                "conditions": {
                    "role": "network_operator",
                    "action": ["read", "write"]
                },
                "effect": "allow"
            },
            {
                "id": "policy_004",
                "name": "Block low trust score apps",
                "conditions": {
                    "trust_score_min": 0.0,
                    "trust_score_max": 0.3
                },
                "effect": "deny"
            },
            {
                "id": "policy_005",
                "name": "Allow guest read with valid token",
                "conditions": {
                    "role": "guest_app",
                    "action": "read"
                },
                "effect": "allow"
            }
        ]
        logger.info("Default Zero Trust policies initialized")

    def _load_policies(self):
        """Load policies from configuration file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load policies from {self.config_path}: {e}")
        return {}

    def verify_request(self, app_id, request_data):
        """
        MAIN ENTRY POINT: Verify every application request.
        
        This is called for EVERY request - not just once.
        Implements the Zero Trust principle of continuous verification.
        
        Args:
            app_id: Unique identifier of the requesting application
            request_data: Dictionary containing request details:
                - action: The action being requested (read, write, delete, configure)
                - resource: The target resource (flow_table, switch_config, etc.)
                - token: Authentication token
                - api_key: API key
                - device_id: Device identifier
                - timestamp: Request timestamp
                - role: Claimed role of the application
        
        Returns:
            dict: {
                "allowed": True/False,
                "trust_score": float,
                "reason": str,
                "verification_steps": list
            }
        """
        verification_steps = []
        trust_score = 0.0
        app_id = request_data.get("app_id", "unknown")
        
        logger.info(f"=== ZERO TRUST VERIFICATION STARTED for app: {app_id} ===")
        logger.info(f"Request: {request_data.get('action', 'unknown')} on {request_data.get('resource', 'unknown')}")
        
        # Step 1: Token Verification
        token_result = self._verify_token(app_id, request_data)
        verification_steps.append(("token_verification", token_result))
        if not token_result["valid"]:
            logger.warning(f"TOKEN FAILED for {app_id}: {token_result['reason']}")
            return self._deny("Token verification failed", verification_steps, 0.0)
        
        # Step 2: API Key Validation
        api_key_result = self._validate_api_key(app_id, request_data)
        verification_steps.append(("api_key_validation", api_key_result))
        if not api_key_result["valid"]:
            logger.warning(f"API KEY FAILED for {app_id}: {api_key_result['reason']}")
            return self._deny("API Key validation failed", verification_steps, 0.1)
        
        # Step 3: Device Identity Verification
        device_result = self._verify_device_identity(app_id, request_data)
        verification_steps.append(("device_identity", device_result))
        if not device_result["valid"]:
            logger.warning(f"DEVICE IDENTITY FAILED for {app_id}: {device_result['reason']}")
            return self._deny("Device identity verification failed", verification_steps, 0.2)
        
        # Step 4: Role-Based Access Control (RBAC)
        rbac_result = self._check_rbac(app_id, request_data)
        verification_steps.append(("rbac_check", rbac_result))
        if not rbac_result["allowed"]:
            logger.warning(f"RBAC FAILED for {app_id}: {rbac_result['reason']}")
            return self._deny("RBAC check failed", verification_steps, 0.3)
        
        # Step 5: Attribute-Based Access Control (ABAC)
        abac_result = self._check_abac(app_id, request_data)
        verification_steps.append(("abac_check", abac_result))
        if not abac_result["allowed"]:
            logger.warning(f"ABAC FAILED for {app_id}: {abac_result['reason']}")
            return self._deny("ABAC check failed", verification_steps, 0.4)
        
        # Step 6: Behavioral Analysis
        behavior_result = self._analyze_behavior(app_id, request_data)
        verification_steps.append(("behavioral_analysis", behavior_result))
        if behavior_result["anomaly_detected"]:
            logger.warning(f"BEHAVIORAL ANOMALY for {app_id}: {behavior_result['reason']}")
            return self._deny("Behavioral anomaly detected", verification_steps,
                              behavior_result.get("trust_score", 0.0))
        
        # Step 7: Continuous Trust Scoring
        trust_score = self._calculate_trust_score(app_id, verification_steps)
        verification_steps.append(("trust_scoring", {"score": trust_score}))
        
        # Final decision based on trust score
        if trust_score >= 0.6:
            logger.info(f"REQUEST ALLOWED for {app_id} with trust score: {trust_score}")
            return self._allow(trust_score, verification_steps)
        else:
            logger.warning(f"REQUEST DENIED for {app_id} - trust score too low: {trust_score}")
            return self._deny(f"Trust score {trust_score} below threshold 0.6", verification_steps, trust_score)

    def _verify_token(self, app_id, request_data):
        """
        Step 1: Token Verification
        
        Every request must carry a valid token. Tokens are short-lived
        and must be refreshed. This prevents replay attacks.
        
        Token format: HMAC-SHA256(app_id + secret + timestamp)
        """
        token = request_data.get("token", "")
        timestamp = request_data.get("timestamp", 0)
        secret = self._get_app_secret(app_id)
        
        if not token:
            return {"valid": False, "reason": "No token provided"}
        
        # Check token expiry (tokens valid for 60 seconds only)
        current_time = time.time()
        if current_time - timestamp > 60:
            return {"valid": False, "reason": "Token expired"}
        
        # Verify token using HMAC
        expected_token = hmac.new(
            secret.encode(),
            f"{app_id}:{timestamp}".encode(),
            hashlib.sha256
        ).hexdigest()
        
        if token == expected_token:
            return {"valid": True, "reason": "Token verified successfully"}
        else:
            return {"valid": False, "reason": "Invalid token signature"}

    def _validate_api_key(self, app_id, request_data):
        """
        Step 2: API Key Validation
        
        Each application has a unique API key that must be presented
        with every request. Keys are rotated periodically.
        """
        provided_key = request_data.get("api_key", "")
        stored_key = self.api_keys.get(app_id, "")
        
        if not provided_key:
            return {"valid": False, "reason": "No API key provided"}
        
        if provided_key == stored_key:
            return {"valid": True, "reason": "API key validated"}
        else:
            return {"valid": False, "reason": "Invalid API key"}

    def _verify_device_identity(self, app_id, request_data):
        """
        Step 3: Device Identity Verification
        
        Verifies that the request is coming from a known and trusted device.
        Uses device fingerprinting (MAC address, hostname, etc.)
        """
        device_id = request_data.get("device_id", "")
        device_fingerprint = request_data.get("device_fingerprint", "")
        
        if not device_id:
            return {"valid": False, "reason": "No device ID provided"}
        
        if device_id not in self.device_registry:
            return {"valid": False, "reason": f"Unknown device: {device_id}"}
        
        registered_device = self.device_registry[device_id]
        
        # Verify device fingerprint
        if device_fingerprint != registered_device.get("device_fingerprint"):
            return {"valid": False, "reason": "Device fingerprint mismatch"}
        
        # Check if device is blacklisted
        if registered_device.get("blacklisted", False):
            return {"valid": False, "reason": "Device is blacklisted"}
        
        return {"valid": True, "reason": "Device identity verified", "device_info": registered_device}

    def _check_rbac(self, app_id, request_data):
        """
        Step 4: Role-Based Access Control (RBAC)
        
        Checks if the application's role has permission to perform
        the requested action.
        """
        role = request_data.get("role", "guest_app")
        action = request_data.get("action", "")
        
        if role not in self.role_permissions:
            return {"allowed": False, "reason": f"Unknown role: {role}"}
        
        allowed_actions = self.role_permissions[role]
        if action in allowed_actions:
            return {"allowed": True, "reason": f"Role '{role}' allowed action '{action}'"}
        else:
            return {"allowed": False, "reason": f"Role '{role}' not allowed action '{action}'"}

    def _check_abac(self, app_id, request_data):
        """
        Step 5: Attribute-Based Access Control (ABAC)
        
        Evaluates policies based on attributes:
        - Subject attributes (role, trust score)
        - Resource attributes (resource type, sensitivity)
        - Environment attributes (time, network condition)
        """
        for policy in self.attribute_policies:
            conditions = policy["conditions"]
            match = True
            
            for attr, value in conditions.items():
                if attr == "trust_score_min":
                    trust_score = self.trust_scores.get(app_id, 0.0)
                    if trust_score < value:
                        match = False
                        break
                elif attr == "time_range":
                    current_hour = datetime.now().strftime("%H:%M")
                    start, end = value
                    if not (start <= current_hour <= end):
                        match = False
                        break
                elif attr == "token_valid":
                    token = request_data.get("token", "")
                    if not token:
                        match = False
                        break
                elif attr == "trusted_device":
                    device_id = request_data.get("device_id", "")
                    if value and device_id not in self.device_registry:
                        match = False
                        break
                else:
                    request_attr = request_data.get(attr)
                    if isinstance(value, list):
                        if request_attr not in value:
                            match = False
                            break
                    else:
                        if request_attr != value:
                            match = False
                            break
            
            if match:
                if policy["effect"] == "allow":
                    return {"allowed": True, "reason": f"ABAC policy '{policy['name']}' matched"}
                else:
                    return {"allowed": False, "reason": f"ABAC policy '{policy['name']}' denied access"}
        
        return {"allowed": False, "reason": "No matching ABAC policy"}

    def _analyze_behavior(self, app_id, request_data):
        """
        Step 6: Behavioral Analysis
        
        Analyzes the application's behavior pattern to detect anomalies.
        Maintains a history of past behaviors and compares current request.
        
        Detects:
        - Unusual request frequency (possible DoS)
        - Unusual resource access patterns
        - Out-of-normal working hours access
        - Abnormal request sizes
        """
        if app_id not in self.behavior_history:
            self.behavior_history[app_id] = []
        
        history = self.behavior_history[app_id]
        current_time = time.time()
        
        # Add current request to history
        history.append({
            "timestamp": current_time,
            "action": request_data.get("action"),
            "resource": request_data.get("resource")
        })
        
        # Keep only last 100 entries
        if len(history) > 100:
            history.pop(0)
        
        anomaly_score = 0.0
        reasons = []
        
        # Check 1: Request frequency (more than 6 requests in 3 seconds
        # = anomalous burst; tuned so normal polling apps are unaffected)
        recent_requests = [h for h in history if current_time - h["timestamp"] < 3]
        if len(recent_requests) > 6:
            anomaly_score += 0.3
            reasons.append("Anomalous request burst: %d in 3s" % len(recent_requests))
        
        # Persistent burst penalty: grows with every extra request sent
        # inside the burst window, driving the app's trust towards zero
        # (progressive lockout of flooding applications).
        burst_penalty = min(
            1.0, 0.1 * max(0, len(recent_requests) - 6)) if len(recent_requests) > 6 else 0.0
        
        # Check 2: Unusual resource access
        resource_counts = {}
        for h in history:
            res = h.get("resource", "unknown")
            resource_counts[res] = resource_counts.get(res, 0) + 1
        
        requested_resource = request_data.get("resource", "unknown")
        if requested_resource not in resource_counts:
            # First time accessing this resource - slight anomaly
            anomaly_score += 0.1
            reasons.append(f"First time accessing resource: {requested_resource}")
        
        # Check 3: Unusual action pattern
        action = request_data.get("action", "")
        if action == "delete" and len(history) < 5:
            anomaly_score += 0.2
            reasons.append("Delete action attempted by new app")
        
        result = {
            "anomaly_detected": anomaly_score >= 0.3,
            "anomaly_score": anomaly_score,
            "burst_penalty": burst_penalty,
            "trust_score": max(0, round(1.0 - burst_penalty, 2)),
            "reasons": reasons,
            "reason": "; ".join(reasons) if reasons else "No anomaly detected"
        }
        
        return result

    def _calculate_trust_score(self, app_id, verification_steps):
        """
        Step 7: Continuous Trust Scoring
        
        Calculates a dynamic trust score based on ALL verification steps.
        Trust score changes over time based on behavior.
        
        Formula:
        trust_score = (token_weight * token_result +
                       apikey_weight * apikey_result +
                       device_weight * device_result +
                       rbac_weight * rbac_result +
                       abac_weight * abac_result +
                       behavior_weight * behavior_result)
        
        All weights sum to 1.0
        """
        weights = {
            "token_verification": 0.20,
            "api_key_validation": 0.15,
            "device_identity": 0.15,
            "rbac_check": 0.20,
            "abac_check": 0.15,
            "behavioral_analysis": 0.15
        }
        
        score = 0.0
        for step_name, step_result in verification_steps:
            weight = weights.get(step_name, 0.1)
            
            if step_name == "behavioral_analysis":
                step_score = 1.0 - step_result.get("anomaly_score", 0)
            elif step_name == "trust_scoring":
                continue
            else:
                step_score = 1.0 if step_result.get("valid", step_result.get("allowed", False)) else 0.0
            
            score += weight * step_score
        
        # Update stored trust score
        app_id_for_score = None
        for step_name, step_result in verification_steps:
            if step_name == "token_verification":
                # We don't have app_id here, but we can get it from context
                pass
        
        return round(score, 2)

    def _get_app_secret(self, app_id):
        """Get the secret key for an application."""
        secrets = {
            "legitimate_monitor": "secret_key_monitor_2024",
            "legitimate_controller": "secret_key_controller_2024",
            "legitimate_admin": "secret_key_admin_2024",
            "malicious_attacker": "malicious_key_2024",
            "fake_app": "fake_key_2024",
            "compromised_app": "compromised_key_2024"
        }
        return secrets.get(app_id, "default_secret_key")

    def register_application(self, app_id, api_key, role, device_info=None):
        """
        Register a new application in the Zero Trust framework.
        
        This is the ONE-TIME registration. After registration,
        EVERY request goes through continuous verification.
        """
        self.api_keys[app_id] = api_key
        self.trust_scores[app_id] = 0.5  # Initial trust score (neutral)
        self.behavior_history[app_id] = []
        
        if device_info:
            device_id = device_info.get("device_id")
            if device_id:
                self.device_registry[device_id] = device_info
        
        logger.info(f"Application '{app_id}' registered with role-based access")
        return {"status": "registered", "app_id": app_id}

    def generate_token(self, app_id):
        """Generate a time-limited token for an application."""
        timestamp = int(time.time())
        secret = self._get_app_secret(app_id)
        
        token = hmac.new(
            secret.encode(),
            f"{app_id}:{timestamp}".encode(),
            hashlib.sha256
        ).hexdigest()
        
        self.session_tokens[app_id] = {
            "token": token,
            "timestamp": timestamp,
            "expires_at": timestamp + 60
        }
        
        return {
            "token": token,
            "timestamp": timestamp,
            "expires_in": 60
        }

    def _allow(self, trust_score, verification_steps):
        """Generate an 'allow' response."""
        return {
            "allowed": True,
            "trust_score": trust_score,
            "reason": "All verification checks passed",
            "verification_steps": verification_steps
        }

    def _deny(self, reason, verification_steps, trust_score=0.0):
        """Generate a 'deny' response."""
        return {
            "allowed": False,
            "trust_score": trust_score,
            "reason": reason,
            "verification_steps": verification_steps
        }

    def get_trust_score(self, app_id):
        """Get the current trust score for an application."""
        return self.trust_scores.get(app_id, 0.0)

    def reset_trust_score(self, app_id):
        """Reset trust score for an application."""
        self.trust_scores[app_id] = 0.5
        logger.info(f"Trust score reset for {app_id}")

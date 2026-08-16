"""
policy_engine.py - Zero Trust Policy Engine
============================================
The Policy Engine is responsible for:
1. Defining trust policies
2. Evaluating requests against policies
3. Making access decisions based on policies
4. Dynamically updating policies based on trust scores

In Zero Trust architecture, the Policy Engine is the brain
that decides whether to allow or deny every request.
"""

import json
import os
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PolicyEngine")


class PolicyEngine:
    """
    Zero Trust Policy Engine
    
    The Policy Engine evaluates every request against defined policies
    and makes access decisions. It works closely with:
    - TrustVerificationEngine (for trust scores)
    - PolicyAdministrator (for policy management)
    - PolicyEnforcementPoint (for enforcement)
    
    Key Zero Trust Principle:
    "Access decisions are based on dynamic policies, not static rules"
    """

    def __init__(self, trust_verification_engine=None):
        self.trust_engine = trust_verification_engine
        self.policies = self._initialize_policies()
        self.policy_history = []
        logger.info("Policy Engine initialized")

    def _initialize_policies(self):
        """Initialize the policy database."""
        return {
            "access_policies": [
                {
                    "id": "POL-001",
                    "name": "Flow Table Read Access",
                    "description": "Allow reading flow table entries",
                    "conditions": {
                        "allowed_roles": ["admin", "network_operator", "monitoring_app"],
                        "min_trust_score": 0.5,
                        "allowed_actions": ["read"],
                        "resources": ["flow_table", "flow_stats"]
                    },
                    "effect": "allow",
                    "priority": 10
                },
                {
                    "id": "POL-002",
                    "name": "Flow Table Write Access",
                    "description": "Allow modifying flow table entries",
                    "conditions": {
                        "allowed_roles": ["admin", "network_operator"],
                        "min_trust_score": 0.7,
                        "allowed_actions": ["write", "delete"],
                        "resources": ["flow_table", "switch_config"]
                    },
                    "effect": "allow",
                    "priority": 20
                },
                {
                    "id": "POL-003",
                    "name": "Controller Configuration Access",
                    "description": "Allow configuring the controller",
                    "conditions": {
                        "allowed_roles": ["admin"],
                        "min_trust_score": 0.8,
                        "allowed_actions": ["configure"],
                        "resources": ["controller_config", "switch_config"]
                    },
                    "effect": "allow",
                    "priority": 30
                },
                {
                    "id": "POL-004",
                    "name": "Default Deny All",
                    "description": "Deny all requests that don't match any policy",
                    "conditions": {},
                    "effect": "deny",
                    "priority": 100
                }
            ],
            "trust_thresholds": {
                "minimum_trust_score": 0.6,
                "medium_trust_score": 0.7,
                "high_trust_score": 0.85
            },
            "verification_requirements": {
                "read": ["token", "api_key", "device_id"],
                "write": ["token", "api_key", "device_id", "rbac"],
                "delete": ["token", "api_key", "device_id", "rbac", "abac"],
                "configure": ["token", "api_key", "device_id", "rbac", "abac", "behavioral"]
            }
        }
        logger.info("Policy Engine initialized with Zero Trust policies")

    def evaluate_request(self, app_id, request_data, trust_verdict):
        """
        Evaluate a request against all policies.
        
        This is the main decision-making function.
        It considers:
        1. The trust verification result
        2. The specific policies for the requested action
        3. The current trust score
        4. Environmental factors (time, network load, etc.)
        
        Returns:
            dict: {
                "decision": "allow" or "deny",
                "matched_policy": str,
                "reason": str,
                "enforcement_action": str
            }
        """
        action = request_data.get("action", "")
        resource = request_data.get("resource", "")
        role = request_data.get("role", "guest_app")
        trust_score = trust_verdict.get("trust_score", 0.0)
        
        logger.info(f"Policy Engine evaluating: {app_id} -> {action} on {resource}")
        
        # Sort policies by priority (lower number = higher priority)
        sorted_policies = sorted(
            self.policies["access_policies"],
            key=lambda p: p["priority"]
        )
        
        for policy in sorted_policies:
            if self._policy_matches(policy, request_data, trust_score):
                if policy["effect"] == "allow":
                    logger.info(f"Policy {policy['id']} ALLOWED request")
                    return {
                        "decision": "allow",
                        "matched_policy": policy["id"],
                        "policy_name": policy["name"],
                        "reason": f"Matched policy: {policy['name']}",
                        "enforcement_action": "forward_to_controller"
                    }
                else:
                    logger.warning(f"Policy {policy['id']} DENIED request")
                    return {
                        "decision": "deny",
                        "matched_policy": policy["id"],
                        "policy_name": policy["name"],
                        "reason": f"Denied by policy: {policy['name']}",
                        "enforcement_action": "drop_packet"
                    }
        
        # Default: deny if no policy matches
        logger.warning(f"No matching policy for {app_id} - default deny")
        return {
            "decision": "deny",
            "matched_policy": "default",
            "policy_name": "Default Deny",
            "reason": "No matching policy found - default deny",
            "enforcement_action": "drop_packet"
        }

    def _policy_matches(self, policy, request_data, trust_score):
        """Check if a policy matches the current request."""
        conditions = policy["conditions"]
        
        if not conditions:
            return True  # Default policy
        
        # Check role
        if "allowed_roles" in conditions:
            role = request_data.get("role", "")
            if role not in conditions["allowed_roles"]:
                return False
        
        # Check trust score
        if "min_trust_score" in conditions:
            if trust_score < conditions["min_trust_score"]:
                return False
        
        # Check action
        if "allowed_actions" in conditions:
            action = request_data.get("action", "")
            if action not in conditions["allowed_actions"]:
                return False
        
        # Check resource
        if "resources" in conditions:
            resource = request_data.get("resource", "")
            if resource not in conditions["resources"]:
                return False
        
        return True

    def add_policy(self, policy):
        """Add a new policy to the engine."""
        self.policies["access_policies"].append(policy)
        logger.info(f"New policy added: {policy['name']}")

    def remove_policy(self, policy_id):
        """Remove a policy by ID."""
        self.policies["access_policies"] = [
            p for p in self.policies["access_policies"]
            if p["id"] != policy_id
        ]
        logger.info(f"Policy {policy_id} removed")

    def get_policies(self):
        """Get all current policies."""
        return self.policies

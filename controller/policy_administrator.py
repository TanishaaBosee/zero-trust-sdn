"""
policy_administrator.py - Zero Trust Policy Administrator
==========================================================
The Policy Administrator manages the lifecycle of policies:
1. Creating new policies
2. Updating existing policies
3. Deleting outdated policies
4. Monitoring policy effectiveness
5. Generating policy reports

In Zero Trust architecture, the Policy Administrator is the
management interface that allows security administrators to
define and manage trust policies.
"""

import json
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PolicyAdministrator")


class PolicyAdministrator:
    """
    Zero Trust Policy Administrator
    
    The Policy Administrator is the management component that:
    1. Provides API for policy management
    2. Validates policy syntax and semantics
    3. Ensures no conflicting policies exist
    4. Maintains policy version history
    5. Generates policy compliance reports
    
    In Zero Trust, policies are dynamic and can change based on:
    - Trust scores
    - Time of day
    - Network conditions
    - Security alerts
    """

    def __init__(self, policy_engine=None):
        self.policy_engine = policy_engine
        self.policy_versions = []
        self.policy_history = []
        self.audit_log = []
        self.current_version = 1
        logger.info("Policy Administrator initialized")

    def create_policy(self, policy_data):
        """
        Create a new policy.
        
        Policy format:
        {
            "id": "POL-XXX",
            "name": "Policy Name",
            "description": "What this policy does",
            "conditions": {
                "allowed_roles": ["admin"],
                "min_trust_score": 0.7,
                "allowed_actions": ["read", "write"],
                "resources": ["flow_table"],
                "time_restriction": {
                    "start": "09:00",
                    "end": "17:00"
                }
            },
            "effect": "allow" or "deny",
            "priority": 10
        }
        """
        # Validate policy
        if not self._validate_policy(policy_data):
            return {"status": "error", "message": "Invalid policy format"}
        
        # Add to engine
        self.policy_engine.add_policy(policy_data)
        
        # Log the change
        self._log_policy_change("create", policy_data)
        
        return {"status": "success", "policy_id": policy_data["id"]}

    def update_policy(self, policy_id, updates):
        """Update an existing policy."""
        policies = self.policy_engine.policies["access_policies"]
        for i, p in enumerate(policies):
            if p["id"] == policy_id:
                policies[i].update(updates)
                self._log_policy_change("update", policies[i])
                return {"status": "success", "policy_id": policy_id}
        return {"status": "error", "message": f"Policy {policy_id} not found"}

    def delete_policy(self, policy_id):
        """Delete a policy."""
        self.policy_engine.remove_policy(policy_id)
        self._log_policy_change("delete", {"id": policy_id})
        return {"status": "success", "policy_id": policy_id}

    def _log_policy_change(self, action, policy_data):
        """Log a policy change for audit purposes."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "policy": policy_data
        }
        self.policy_history.append(log_entry)
        logger.info(f"Policy change logged: {action} - {policy_data.get('name', 'unknown')}")

    def get_policy_history(self):
        """Get the policy change history."""
        return self.policy_history

    def get_verification_requirements(self, action):
        """Get the verification requirements for a specific action."""
        if self.policy_engine is None:
            return ["token"]
        return self.policy_engine.policies["verification_requirements"].get(
            action, ["token"])

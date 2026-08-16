"""
policy_enforcement_point.py - Zero Trust Policy Enforcement Point (PEP)
========================================================================
The Policy Enforcement Point (PEP) is the component that:
1. Intercepts all requests between applications and the SDN controller
2. Enforces the decisions made by the Policy Engine
3. Blocks or allows traffic based on policy decisions
4. Logs all enforcement actions for audit

In Zero Trust architecture, the PEP is the guard that physically
enforces the "never trust, always verify" principle at the
network level.

The PEP sits between:
- Applications (that want to communicate with the controller)
- The SDN Controller (that manages the network)

Every packet must pass through the PEP before reaching the controller.
"""

import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PolicyEnforcementPoint")


class PolicyEnforcementPoint:
    """
    Zero Trust Policy Enforcement Point (PEP)
    
    The PEP is the enforcement arm of the Zero Trust framework.
    It sits between applications and the SDN controller and:
    
    1. Intercepts ALL requests from applications
    2. Sends requests to TrustVerificationEngine for verification
    3. Sends verified requests to PolicyEngine for decision
    4. ENFORCES the decision (allow/deny)
    5. Logs all enforcement actions
    6. Generates alerts for denied requests
    
    In SDN context, the PEP can be implemented as:
    - A module in the RYU controller
    - An OpenFlow rule generator
    - A middleware between apps and controller
    """

    def __init__(self, trust_engine=None, policy_engine=None):
        self.trust_engine = trust_engine
        self.policy_engine = policy_engine
        self.enforcement_log = []
        self.blocked_requests = 0
        self.allowed_requests = 0
        self.active_flow_rules = {}
        logger.info("Policy Enforcement Point initialized")

    def enforce(self, app_id, request_data):
        """
        Main enforcement function.
        
        This is called for EVERY request. It:
        1. Sends request to Trust Verification Engine
        2. Sends verification result to Policy Engine
        3. Enforces the decision
        4. Logs the enforcement action
        
        Returns:
            dict: {
                "action": "allow" or "deny",
                "reason": str,
                "enforcement_details": dict
            }
        """
        logger.info(f"PEP enforcing request from {app_id}")
        
        # Step 1: Verify trust - fail closed: a negative trust verdict
        # (expired/invalid token, bad API key, unknown device, RBAC/ABAC
        # failure, or a detected behavioral anomaly) denies the request
        # immediately, before any policy matching takes place.
        trust_verdict = self.trust_engine.verify_request(app_id, request_data)
        if not trust_verdict.get("allowed", False):
            enforcement_result = {
                "action": "deny",
                "openflow_action": "DROP",
                "reason": trust_verdict.get("reason", "Trust verification failed"),
                "trust_score": round(trust_verdict.get("trust_score", 0.0), 2),
                "verification_steps": trust_verdict.get("verification_steps", [])
            }
            self.blocked_requests += 1
            self._log_enforcement(
                app_id, request_data,
                {"decision": "deny", "reason": enforcement_result["reason"]},
                enforcement_result)
            return enforcement_result

        # Step 2: Evaluate policy (only for verified requests)
        policy_decision = self.policy_engine.evaluate_request(
            app_id, request_data, trust_verdict
        )
        
        # Step 3: Enforce the decision
        enforcement_result = self._enforce_decision(
            app_id, request_data, policy_decision
        )
        
        # Step 4: Add full attribution so the caller (and the audit log)
        # sees why the request was allowed or denied and with what score.
        enforcement_result["reason"] = policy_decision.get("reason", "")
        enforcement_result["matched_policy"] = policy_decision.get("matched_policy", "")
        enforcement_result["trust_score"] = round(trust_verdict.get("trust_score", 0.0), 2)
        enforcement_result["verification_steps"] = trust_verdict.get("verification_steps", [])
        
        # Step 5: Log enforcement
        self._log_enforcement(app_id, request_data, policy_decision, enforcement_result)
        
        return enforcement_result

    def _enforce_decision(self, app_id, request_data, policy_decision):
        """
        Enforce the policy decision.
        
        In a real SDN environment, this would:
        1. Install OpenFlow rules to allow/block traffic
        2. Update flow tables on the switch
        3. Send alerts to the security monitoring system
        
        In our simulation, we log the enforcement action.
        """
        decision = policy_decision["decision"]
        enforcement_action = policy_decision["enforcement_action"]
        
        if decision == "allow":
            self.allowed_requests += 1
            return {
                "action": "allow",
                "openflow_action": "OUTPUT_NORMAL",
                "details": f"Request from {app_id} forwarded to controller"
            }
        else:
            self.blocked_requests += 1
            return {
                "action": "deny",
                "openflow_action": "DROP",
                "details": f"Request from {app_id} blocked by PEP"
            }

    def _log_enforcement(self, app_id, request_data, policy_decision, enforcement_result):
        """Log enforcement action for audit."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "app_id": app_id,
            "request": request_data,
            "decision": policy_decision,
            "enforcement": enforcement_result
        }
        self.enforcement_log.append(log_entry)
        
        if enforcement_result["action"] == "deny":
            logger.warning(f"BLOCKED: {app_id} - {request_data.get('action')} - {policy_decision['reason']}")
        else:
            logger.info(f"ALLOWED: {app_id} - {request_data.get('action')}")

    def get_enforcement_stats(self):
        """Get enforcement statistics."""
        return {
            "total_requests": self.allowed_requests + self.blocked_requests,
            "allowed": self.allowed_requests,
            "blocked": self.blocked_requests,
            "block_rate": (self.blocked_requests / max(1, self.allowed_requests + self.blocked_requests)) * 100
        }

    def install_flow_rule(self, switch_id, rule):
        """
        Install an OpenFlow rule on a switch.
        
        In a real SDN environment, this would:
        1. Create an OpenFlow flow mod message
        2. Send it to the switch via the RYU controller
        3. Verify the rule was installed
        
        For simulation, we log the rule installation.
        """
        rule_id = f"rule_{len(self.active_flow_rules) + 1}"
        self.active_flow_rules[rule_id] = {
            "switch_id": switch_id,
            "rule": rule,
            "installed_at": datetime.now().isoformat()
        }
        logger.info(f"OpenFlow rule {rule_id} installed on switch {switch_id}")
        return {"status": "installed", "rule_id": rule_id}

    def remove_flow_rule(self, rule_id):
        """Remove an installed flow rule."""
        if rule_id in self.active_flow_rules:
            del self.active_flow_rules[rule_id]
            logger.info(f"OpenFlow rule {rule_id} removed")
            return {"status": "removed"}
        return {"status": "error", "message": f"Rule {rule_id} not found"}

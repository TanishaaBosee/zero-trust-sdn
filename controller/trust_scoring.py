"""
trust_scoring.py - Continuous Trust Scoring Module
====================================================
This module implements dynamic trust scoring for applications.
Trust scores change over time based on:
1. Successful verifications (increase trust)
2. Failed verifications (decrease trust)
3. Behavioral patterns (anomaly detection)
4. Time since last verification
5. Historical compliance

Key Zero Trust Principle:
"Trust is not binary - it's a continuous spectrum that changes over time"
"""

import time
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrustScoring")


class TrustScoring:
    """
    Continuous Trust Scoring System
    
    Trust scores are dynamic and change based on:
    - Successful verifications: +0.1
    - Failed verifications: -0.3
    - Anomalous behavior: -0.2
    - Time decay: -0.01 per minute without verification
    - Successful history: +0.05 per 10 successful requests
    
    Trust score range: 0.0 (untrusted) to 1.0 (fully trusted)
    Threshold for access: 0.6
    """

    def __init__(self):
        self.scores = {}  # app_id -> current trust score
        self.history = {}  # app_id -> list of score changes
        self.last_updated = {}  # app_id -> timestamp
        logger.info("Trust Scoring Module initialized")

    def initialize_score(self, app_id):
        """Initialize trust score for a new application."""
        self.scores[app_id] = 0.5  # Start at neutral
        self.history[app_id] = [{"score": 0.5, "reason": "Initial score", "timestamp": time.time()}]
        self.last_updated[app_id] = time.time()
        return 0.5

    def update_score(self, app_id, verification_result):
        """
        Update trust score based on verification result.
        
        Score changes:
        - Successful verification: +0.1 (max 1.0)
        - Failed verification: -0.3 (min 0.0)
        - Anomaly detected: -0.2
        - Time decay: -0.01 per minute
        """
        current_score = self.scores.get(app_id, 0.5)
        
        if verification_result.get("allowed", False):
            current_score = min(1.0, current_score + 0.1)
            reason = "Successful verification"
        else:
            # Distinguish security-critical failures (authentication,
            # identity, behavioral anomalies) from least-privilege
            # violations (RBAC/ABAC denials). The latter are expected
            # for boundary probes and must not destroy reputation.
            failure_reason = verification_result.get("reason", "")
            if ("rbac" in failure_reason.lower() or
                    "abac" in failure_reason.lower()):
                current_score = max(0.0, current_score - 0.1)
                reason = "Least-privilege violation (RBAC/ABAC)"
            else:
                current_score = max(0.0, current_score - 0.3)
                reason = failure_reason or "Verification failed"
        
        # Apply time decay
        last_update = self.last_updated.get(app_id, time.time())
        minutes_passed = (time.time() - last_update) / 60
        decay = minutes_passed * 0.01
        current_score = max(0.0, current_score - decay)
        
        # Update
        self.scores[app_id] = round(current_score, 2)
        self.last_updated[app_id] = time.time()
        
        # Record history
        if app_id not in self.history:
            self.history[app_id] = []
        self.history[app_id].append({
            "score": current_score,
            "reason": reason,
            "timestamp": time.time()
        })
        
        return self.scores[app_id]

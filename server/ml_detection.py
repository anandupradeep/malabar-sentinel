"""
Machine Learning Detection Engine
Uses Isolation Forest for anomaly detection and Random Forest for classification
"""

import logging
import random
from typing import Dict, List, Optional

logger = logging.getLogger("ml-detection")

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    logger.warning("scikit-learn not installed - using rule-based fallback")


class MLDetectionEngine:
    def __init__(self):
        self.isolation_forest: Optional[object] = None
        self.random_forest: Optional[object] = None
        self.scaler: Optional[object] = None
        self.initialized = False
        self._alert_count = 0
        self._anomalies_detected = 0

    def initialize(self):
        """Initialize and train ML models with synthetic baseline data"""
        if not HAS_SKLEARN:
            logger.info("ML engine using rule-based mode (sklearn not available)")
            self.initialized = True
            return

        logger.info("Initializing ML models...")
        np.random.seed(42)

        # Generate synthetic normal baseline data
        n_normal = 1000
        normal_data = np.column_stack([
            np.random.normal(5, 2, n_normal),      # cpu_usage (%)
            np.random.normal(50, 15, n_normal),     # memory_usage (%)
            np.random.normal(3, 1, n_normal),       # process_count
            np.random.normal(10, 5, n_normal),      # network_connections
            np.random.normal(2, 1, n_normal),       # file_ops_per_sec
            np.random.normal(1, 0.5, n_normal),     # login_attempts
        ])
        normal_data = np.clip(normal_data, 0, None)

        # Train Isolation Forest
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.scaler = StandardScaler()
        scaled_data = self.scaler.fit_transform(normal_data)
        self.isolation_forest.fit(scaled_data)

        # Train Random Forest classifier with synthetic labeled data
        n_attack = 200
        attack_data = np.column_stack([
            np.random.uniform(80, 100, n_attack),   # high CPU
            np.random.uniform(80, 100, n_attack),   # high memory
            np.random.uniform(50, 200, n_attack),   # many processes
            np.random.uniform(100, 500, n_attack),  # many connections
            np.random.uniform(100, 1000, n_attack), # many file ops
            np.random.uniform(10, 100, n_attack),   # many logins
        ])

        X = np.vstack([normal_data[:n_attack], attack_data])
        y = np.array([0] * n_attack + [1] * n_attack)

        X_scaled = self.scaler.transform(X)
        self.random_forest = RandomForestClassifier(n_estimators=50, random_state=42)
        self.random_forest.fit(X_scaled, y)

        self.initialized = True
        logger.info("ML models trained successfully")

    def extract_features(self, data: dict) -> List[float]:
        """Extract numerical features from alert/event data"""
        return [
            float(data.get("cpu_usage", 5)),
            float(data.get("memory_usage", 50)),
            float(data.get("process_count", 3)),
            float(data.get("network_connections", 10)),
            float(data.get("file_ops", 2)),
            float(data.get("login_attempts", 1)),
        ]

    def score_alert(self, alert_data: dict) -> float:
        """Score an alert (0-1, higher = more suspicious).
        Falls back to rule-based scoring when telemetry features are sparse.
        """
        self._alert_count += 1
        if not self.initialized:
            return 0.5
        if not HAS_SKLEARN:
            return self._rule_based_score(alert_data)

        # Only use ML path when we have real numeric features
        has_rich = any([
            float(alert_data.get("cpu_usage") or 0) > 10,
            float(alert_data.get("memory_usage") or 0) > 10,
            int(alert_data.get("process_pid") or 0) > 0,
            bool(alert_data.get("network_ip")),
            bool(alert_data.get("file_path")),
        ])
        if not has_rich:
            return self._rule_based_score(alert_data)

        try:
            import numpy as np
            features = {
                "cpu_usage":          float(alert_data.get("cpu_usage", 5)),
                "memory_usage":       float(alert_data.get("memory_usage", 50)),
                "process_count":      50.0 if int(alert_data.get("process_pid", 0) or 0) > 10000 else 5.0,
                "network_connections":100.0 if alert_data.get("network_ip") else 10.0,
                "file_ops":           200.0 if alert_data.get("file_path") else 2.0,
                "login_attempts":     20.0  if "login" in (alert_data.get("alert_type") or "") else 1.0,
            }
            feat_arr = np.array(self.extract_features(features)).reshape(1, -1)
            feat_scaled = self.scaler.transform(feat_arr)
            if_score   = self.isolation_forest.decision_function(feat_scaled)[0]
            norm_if    = max(0.0, min(1.0, 0.5 - if_score))
            rf_prob    = self.random_forest.predict_proba(feat_scaled)[0][1]
            ml_signal  = norm_if * 0.6 + rf_prob * 0.4
            sev_floor  = {"emergency":0.92,"critical":0.82,"high":0.68,
                           "medium":0.48,"low":0.22}.get(
                           alert_data.get("severity","low"), 0.22)
            final = min(1.0, ml_signal * 0.50 + sev_floor * 0.50)
            atype = alert_data.get("alert_type","")
            if any(t in atype for t in ["ransomware","credential_dump","process_injection",
                                         "malicious_ip","dll_injection","malware_hash"]):
                final = min(1.0, final + 0.06)
            if final > 0.85:
                self._anomalies_detected += 1
            return round(final, 3)
        except Exception as e:
            logger.error(f"ML scoring error: {e}")
            return self._rule_based_score(alert_data)

    def score_event(self, event: dict) -> float:
        """Score a raw telemetry event"""
        return self.score_alert(event)

    def _rule_based_score(self, data: dict) -> float:
        """Fallback rule-based scoring (no sklearn required)"""
        sev = data.get("severity", "low")
        base = {"emergency": 0.95, "critical": 0.85, "high": 0.70,
                "medium": 0.50, "low": 0.25}.get(sev, 0.25)

        alert_type = data.get("alert_type", "")
        high_risk = ["ransomware", "credential_dump", "process_injection",
                     "malicious_ip", "dll_injection", "process_hollowing", "malware_hash"]
        if any(t in alert_type for t in high_risk):
            base = min(1.0, base + 0.08)

        # Tiny deterministic jitter (avoids random for stable tests)
        jitter = (hash(str(sorted(data.items()))) % 40 - 20) / 1000.0
        return round(min(1.0, max(0.0, base + jitter)), 3)

    def get_stats(self) -> Dict:
        return {
            "initialized": self.initialized,
            "has_sklearn": HAS_SKLEARN,
            "alerts_processed": self._alert_count,
            "anomalies_detected": self._anomalies_detected,
            "models": {
                "isolation_forest": "active" if self.isolation_forest else "inactive",
                "random_forest": "active" if self.random_forest else "inactive",
            }
        }

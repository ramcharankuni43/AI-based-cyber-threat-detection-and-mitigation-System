import os
import sys
import time
import unittest
import numpy as np
import pandas as pd

# Add workspace directory to path
BASE_DIR = os.path.dirname(__file__)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from model_trainer import compute_per_class_metrics, load_and_preprocess_dataset
import inference
from storage.state_store import StateStore
from services.auth_service import authenticate_user, has_permission, hash_password, verify_password
from services.mitigation_service import (
    validate_ip_address,
    is_safe_to_block_ip,
    generate_firewall_rule,
    execute_firewall_rule,
    remove_firewall_rule,
    check_ip_whitelist
)
from services.alert_service import (
    update_incident_status,
    purge_expired_quarantines,
    release_quarantined_ip
)


class TestCyberThreatMitigationSystem(unittest.TestCase):
    """
    Comprehensive automated test suite covering:
    - Normal and attack classification (DDoS, Port Scan, Brute Force)
    - CSV upload validation, missing columns, unknown categoricals, invalid numerics
    - Risk score boundaries and severity tiers
    - SHAP explainability and MITRE ATT&CK technique mapping/fallback
    - Role-based authentication and permission enforcement
    - Incident lifecycle, mitigation failure handling, and release/expiry synchronization
    - Audit logging integrity and JSON state persistence/recovery
    """

    def setUp(self):
        inference.load_all_artifacts()

    # -------------------------------------------------------------
    # Test 1: Normal traffic classification
    # -------------------------------------------------------------
    def test_01_normal_traffic_detection(self):
        """Test 1: Benign network flow is classified as Normal with Low risk (< 30.0)."""
        normal_flow = {
            "src_ip": "192.168.1.45",
            "dst_ip": "10.0.0.5",
            "proto": "tcp",
            "service": "http",
            "state": "FIN",
            "rate": 10.0,
            "spkts": 10.0,
            "dpkts": 12.0,
            "sbytes": 500.0,
            "dbytes": 1000.0,
            "dur": 0.5,
            "failed_login_count": 0,
            "connection_count": 1
        }
        res = inference.analyze_event(normal_flow)
        self.assertEqual(res["predicted_threat"], "Normal")
        self.assertEqual(res["risk_level"], "Low")
        self.assertLess(res["risk_score"], 30.0)
        self.assertEqual(res["action_code"], "LOG_ONLY")

    # -------------------------------------------------------------
    # Test 2: DDoS attack detection
    # -------------------------------------------------------------
    def test_02_ddos_detection(self):
        """Test 2: High-rate volumetric attack flow is identified as an attack with high confidence."""
        df_sample = pd.read_csv(os.path.join(BASE_DIR, "data", "ddos.csv"))
        attack_sample = df_sample.iloc[0].to_dict()
        res = inference.analyze_event(attack_sample)
        self.assertIn(res["predicted_threat"], ["DoS/DDoS", "Port Scan", "Brute Force", "Botnet", "Exploits"])
        self.assertGreaterEqual(res["risk_score"], 30.0)
        self.assertGreater(res["confidence"], 0.5)

    # -------------------------------------------------------------
    # Test 3: Port scan detection
    # -------------------------------------------------------------
    def test_03_port_scan_detection(self):
        """Test 3: Port scan reconnaissance flow is classified as Port Scan."""
        df_sample = pd.read_csv(os.path.join(BASE_DIR, "data", "portscan.csv"))
        scan_sample = df_sample.iloc[0].to_dict()
        res = inference.analyze_event(scan_sample)
        self.assertEqual(res["predicted_threat"], "Port Scan")
        self.assertGreaterEqual(res["risk_score"], 30.0)
        self.assertGreater(res["confidence"], 0.5)

    # -------------------------------------------------------------
    # Test 4: Brute force detection
    # -------------------------------------------------------------
    def test_04_brute_force_detection(self):
        """Test 4: High failed login attempts flow is classified as Brute Force."""
        df_sample = pd.read_csv(os.path.join(BASE_DIR, "data", "bruteforce.csv"))
        brute_sample = df_sample.iloc[0].to_dict()
        res = inference.analyze_event(brute_sample)
        self.assertEqual(res["predicted_threat"], "Brute Force")
        self.assertGreaterEqual(res["risk_score"], 30.0)
        self.assertGreater(res["confidence"], 0.5)

    # -------------------------------------------------------------
    # Test 5: CSV upload validation
    # -------------------------------------------------------------
    def test_05_csv_upload_validation(self):
        """Test 5: Valid CSV upload passes schema verification and metadata extraction."""
        df_valid = pd.read_csv(os.path.join(BASE_DIR, "data", "normal.csv")).head(20)
        res = inference.validate_and_prepare_csv(df_valid)
        self.assertTrue(res["valid"])
        self.assertEqual(res["total_rows"], 20)
        self.assertEqual(len(res["cleaned_df"]), 20)
        self.assertEqual(res["invalid_ip_count"], 0)
        self.assertIn("Validated 20 flow rows", res["summary_message"])

    # -------------------------------------------------------------
    # Test 6: Missing columns rejection
    # -------------------------------------------------------------
    def test_06_missing_columns_rejection(self):
        """Test 6: Reject CSV missing essential network flow columns."""
        df_invalid = pd.DataFrame({
            "employee_id": [101, 102],
            "department": ["Engineering", "Finance"]
        })
        res = inference.validate_and_prepare_csv(df_invalid)
        self.assertFalse(res["valid"])
        self.assertIn("Invalid dataset schema", res["summary_message"])

    # -------------------------------------------------------------
    # Test 7: Unknown categories handling
    # -------------------------------------------------------------
    def test_07_unknown_categories_handling(self):
        """Test 7: Unseen categoricals map safely to code 0 without raising exceptions."""
        flow = {
            "src_ip": "198.51.100.22",
            "dst_ip": "10.0.0.5",
            "proto": "nonexistent_protocol_xyz",
            "service": "shadow_broker_daemon",
            "state": "CUSTOM_INVENTED_FLAG"
        }
        df_row, unseen = inference.prepare_feature_row(flow, return_unseen=True)
        self.assertEqual(df_row["proto_code"].iloc[0], 0.0)
        self.assertEqual(df_row["service_code"].iloc[0], 0.0)
        self.assertEqual(df_row["state_code"].iloc[0], 0.0)
        self.assertGreaterEqual(len(unseen), 3)

        res = inference.analyze_event(flow)
        self.assertIn("predicted_threat", res)
        self.assertIn("risk_score", res)

    # -------------------------------------------------------------
    # Test 8: Invalid numeric and negative values
    # -------------------------------------------------------------
    def test_08_invalid_numeric_and_negative_values(self):
        """Test 8: Handle inf, -inf, NaN, and negative values safely without failure."""
        df_bad = pd.DataFrame([{
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.5",
            "proto": "tcp",
            "service": "http",
            "state": "FIN",
            "rate": np.inf,
            "spkts": "corrupt_string_val",
            "dpkts": np.nan,
            "sbytes": -500.0,
            "dbytes": 1000.0,
            "dur": -0.5
        }])
        res = inference.validate_and_prepare_csv(df_bad)
        self.assertTrue(res["valid"])
        self.assertGreater(res["infinite_count"], 0)
        self.assertGreater(res["coerced_nan_count"], 0)
        self.assertGreater(len(res["range_violations"]), 0)

    # -------------------------------------------------------------
    # Test 9: Risk score boundaries
    # -------------------------------------------------------------
    def test_09_risk_score_boundaries(self):
        """Test 9: Verify risk scores strictly remain bounded between 0.0 and 100.0."""
        extreme_flows = [
            {"rate": 1e9, "sbytes": 1e12, "failed_login_count": 5000},
            {"rate": 0.0, "sbytes": 0.0, "spkts": 0.0, "dur": 0.0},
            {"proto": "udp", "rate": 50000.0, "sbytes": 2000000.0}
        ]
        for flow in extreme_flows:
            res = inference.analyze_event(flow)
            self.assertGreaterEqual(res["risk_score"], 0.0)
            self.assertLessEqual(res["risk_score"], 100.0)

    # -------------------------------------------------------------
    # Test 10: Severity mapping tiers
    # -------------------------------------------------------------
    def test_10_severity_mapping_tiers(self):
        """Test 10: Verify risk score mapping to severity tiers (Low, Medium, High, Critical)."""
        test_cases = [
            (0.0, "Low"),
            (29.9, "Low"),
            (30.0, "Medium"),
            (59.9, "Medium"),
            (60.0, "High"),
            (79.9, "High"),
            (80.0, "Critical"),
            (100.0, "Critical")
        ]
        for score, expected_tier in test_cases:
            tier = inference.get_risk_level_from_score(score)
            self.assertEqual(tier, expected_tier, f"Score {score} expected {expected_tier}, got {tier}")

    # -------------------------------------------------------------
    # Test 11: SHAP explanation handling
    # -------------------------------------------------------------
    def test_11_shap_explanation_handling(self):
        """Test 11: Verify SHAP feature attribution generation, base value, and impact directions."""
        flow = {
            "src_ip": "198.51.100.99",
            "rate": 1500.0,
            "spkts": 200.0,
            "sbytes": 80000.0,
            "dur": 0.8,
            "proto": "tcp",
            "service": "http"
        }
        res = inference.analyze_event(flow)
        shap_data = res.get("shap_explanation", {})
        self.assertIn("top_features", shap_data)
        self.assertGreater(len(shap_data["top_features"]), 0)
        first_feat = shap_data["top_features"][0]
        self.assertIn("feature", first_feat)
        self.assertIn("shap_value", first_feat)
        self.assertIn("impact_direction", first_feat)
        self.assertTrue(first_feat["impact_direction"].startswith(("Toward", "Away from")))
        self.assertIsInstance(shap_data.get("base_value", 0.0), (int, float))

    # -------------------------------------------------------------
    # Test 12: MITRE ATT&CK mapping & fallback
    # -------------------------------------------------------------
    def test_12_mitre_attack_mapping_and_fallback(self):
        """Test 12: Verify MITRE parent-child consistency and fallback for unknown threats."""
        threat_classes = ["DoS/DDoS", "Port Scan", "Brute Force", "Botnet", "Exploits"]
        for threat in threat_classes:
            mitre = inference.get_mitre_mapping(threat)
            tech_id = mitre["technique_id"]
            sub_tech = mitre["sub_technique"]
            self.assertTrue(
                sub_tech.startswith(tech_id),
                f"Parent {tech_id} does not match sub-technique {sub_tech} for threat {threat}"
            )
            self.assertTrue(mitre["url"].startswith("https://attack.mitre.org/techniques/"))

        # Fallback test for unknown / unclassified threats
        unknown_mitre = inference.get_mitre_mapping("ZeroDayX")
        self.assertEqual(unknown_mitre["technique_id"], "T1000")
        self.assertEqual(unknown_mitre["technique_name"], "Unclassified Malicious Network Activity")

    # -------------------------------------------------------------
    # Test 13: Admin login
    # -------------------------------------------------------------
    def test_13_admin_login(self):
        """Test 13: Admin authentication succeeds with valid credentials and returns admin role."""
        auth = authenticate_user("admin", "admin123")
        self.assertIsNotNone(auth)
        self.assertEqual(auth["role"], "admin")
        self.assertEqual(auth["username"], "admin")

        bad_auth = authenticate_user("admin", "wrongpassword")
        self.assertIsNone(bad_auth)

    # -------------------------------------------------------------
    # Test 14: Analyst login
    # -------------------------------------------------------------
    def test_14_analyst_login(self):
        """Test 14: Analyst authentication succeeds with valid credentials and returns analyst role."""
        auth = authenticate_user("analyst", "analyst123")
        self.assertIsNotNone(auth)
        self.assertEqual(auth["role"], "analyst")
        self.assertEqual(auth["username"], "analyst")

    # -------------------------------------------------------------
    # Test 15: Permission restrictions
    # -------------------------------------------------------------
    def test_15_permission_restrictions(self):
        """Test 15: Role permission enforcement restricts analysts from administrative actions."""
        # Admin permissions
        self.assertTrue(has_permission("admin", "retrain_models"))
        self.assertTrue(has_permission("admin", "clear_demo_state"))
        self.assertTrue(has_permission("admin", "approve_quarantine"))
        self.assertFalse(has_permission("admin", "toggle_real_firewall")) # Safe demo restriction

        # Analyst restrictions
        self.assertFalse(has_permission("analyst", "retrain_models"))
        self.assertFalse(has_permission("analyst", "clear_demo_state"))
        self.assertFalse(has_permission("analyst", "toggle_real_firewall"))
        self.assertTrue(has_permission("analyst", "approve_quarantine"))

        # Guest restrictions
        self.assertFalse(has_permission("guest", "approve_quarantine"))
        self.assertFalse(has_permission("guest", "retrain_models"))

    # -------------------------------------------------------------
    # Test 16: Successful quarantine
    # -------------------------------------------------------------
    def test_16_successful_quarantine(self):
        """Test 16: Valid external threat IP is quarantined, incident marked Mitigated, logged SUCCESS."""
        state = {
            "incidents": [
                {
                    "incident_id": "INC-0100",
                    "src_ip": "198.51.100.55",
                    "status": "New",
                    "predicted_threat": "DoS/DDoS",
                    "risk_score": 88.0,
                    "severity": "Critical"
                }
            ],
            "blocklist": {},
            "audit_logs": [],
            "dismissed_ips": set()
        }
        res = update_incident_status(state, "INC-0100", "Mitigated", actor="Admin Alice")
        self.assertTrue(res["success"])
        self.assertIn("198.51.100.55", state["blocklist"])
        self.assertEqual(state["incidents"][0]["status"], "Mitigated")
        self.assertGreaterEqual(len(state["audit_logs"]), 1)
        self.assertEqual(state["audit_logs"][0]["result"], "SUCCESS")
        self.assertEqual(state["audit_logs"][0]["action"], "INCIDENT_MITIGATED")

    # -------------------------------------------------------------
    # Test 17: Rejected quarantine
    # -------------------------------------------------------------
    def test_17_rejected_quarantine(self):
        """Test 17: Mitigating protected IP is rejected, preserves incident status, logs REJECTED."""
        state = {
            "incidents": [
                {
                    "incident_id": "INC-0101",
                    "src_ip": "10.0.0.1", # Protected Gateway IP
                    "status": "Investigating",
                    "predicted_threat": "DoS/DDoS",
                    "risk_score": 92.0,
                    "severity": "Critical"
                }
            ],
            "blocklist": {},
            "audit_logs": [],
            "dismissed_ips": set()
        }
        res = update_incident_status(state, "INC-0101", "Mitigated", actor="Analyst Bob")
        self.assertFalse(res["success"])
        self.assertIn("rejected", res.get("message", "").lower())
        self.assertNotIn("10.0.0.1", state["blocklist"])
        self.assertEqual(state["incidents"][0]["status"], "Investigating")
        self.assertGreaterEqual(len(state["audit_logs"]), 1)
        self.assertEqual(state["audit_logs"][0]["result"], "REJECTED")
        self.assertEqual(state["audit_logs"][0]["action"], "INCIDENT_MITIGATION_REJECTED")

    # -------------------------------------------------------------
    # Test 18: Protected IP rejection
    # -------------------------------------------------------------
    def test_18_protected_ip_rejection(self):
        """Test 18: Verify built-in safety rules reject loopback, broadcast, gateway, and DNS."""
        protected_ips = ["127.0.0.1", "0.0.0.0", "255.255.255.255", "10.0.0.1", "8.8.8.8", "10.0.0.5"]
        for ip in protected_ips:
            safe, reason = is_safe_to_block_ip(ip)
            self.assertFalse(safe, f"Expected {ip} to be unsafe to block")
            rule_res = generate_firewall_rule(ip)
            self.assertFalse(rule_res["valid"], f"Expected rule generation to fail for {ip}")

    # -------------------------------------------------------------
    # Test 19: Successful IP release
    # -------------------------------------------------------------
    def test_19_successful_ip_release(self):
        """Test 19: Manually releasing quarantined IP removes it from blocklist and updates incident."""
        state = {
            "blocklist": {
                "198.51.100.66": {
                    "quarantined_at": time.time(),
                    "ttl_seconds": 3600,
                    "status": "BLOCKED (Simulated Mitigation)"
                }
            },
            "incidents": [
                {
                    "incident_id": "INC-0102",
                    "src_ip": "198.51.100.66",
                    "mitigation_status": "SIMULATED QUARANTINED",
                    "status": "Mitigated"
                }
            ],
            "audit_logs": []
        }
        res = release_quarantined_ip(state, "198.51.100.66", actor="SOC Admin", reason="Manual unblock verification")
        self.assertTrue(res["success"])
        self.assertNotIn("198.51.100.66", state["blocklist"])
        self.assertEqual(state["incidents"][0]["mitigation_status"], "RELEASED (Manual Unblock)")
        self.assertGreaterEqual(len(state["audit_logs"]), 1)
        self.assertEqual(state["audit_logs"][0]["action"], "MANUAL_RELEASE")
        self.assertEqual(state["audit_logs"][0]["result"], "RELEASED")

    # -------------------------------------------------------------
    # Test 20: Quarantine expiry
    # -------------------------------------------------------------
    def test_20_quarantine_expiry(self):
        """Test 20: Purging expired quarantines past 1-hour TTL releases entries and updates incidents."""
        now = time.time()
        blocklist = {
            "198.51.100.77": {
                "quarantined_at": now - 4000, # Expired (past 3600s TTL)
                "ttl_seconds": 3600,
                "status": "BLOCKED (Simulated Mitigation)"
            },
            "198.51.100.88": {
                "quarantined_at": now - 500,  # Active
                "ttl_seconds": 3600,
                "status": "BLOCKED (Simulated Mitigation)"
            }
        }
        incidents = [
            {
                "incident_id": "INC-0103",
                "src_ip": "198.51.100.77",
                "mitigation_status": "SIMULATED QUARANTINED"
            }
        ]
        audit_logs = []
        released = purge_expired_quarantines(blocklist, audit_logs, incidents=incidents)
        self.assertIn("198.51.100.77", released)
        self.assertNotIn("198.51.100.77", blocklist)
        self.assertIn("198.51.100.88", blocklist)
        self.assertEqual(incidents[0]["mitigation_status"], "EXPIRED (TTL Lease)")
        self.assertTrue(any(log["action"] == "QUARANTINE_EXPIRED" and log["target"] == "198.51.100.77" for log in audit_logs))

    # -------------------------------------------------------------
    # Test 21: Incident status transitions
    # -------------------------------------------------------------
    def test_21_incident_status_transitions(self):
        """Test 21: Incident progresses through lifecycle states (New -> Investigating -> Dismissed)."""
        state = {
            "incidents": [
                {
                    "incident_id": "INC-0104",
                    "src_ip": "198.51.100.90",
                    "status": "New",
                    "predicted_threat": "Port Scan",
                    "risk_score": 65.0,
                    "severity": "High"
                }
            ],
            "blocklist": {},
            "audit_logs": [],
            "dismissed_ips": set()
        }
        # Transition 1: New -> Investigating
        res1 = update_incident_status(state, "INC-0104", "Investigating", actor="Analyst 1", analyst_notes="Triaging anomaly")
        self.assertTrue(res1["success"])
        self.assertEqual(state["incidents"][0]["status"], "Investigating")

        # Transition 2: Investigating -> Dismissed
        res2 = update_incident_status(state, "INC-0104", "Dismissed", actor="Analyst 1", analyst_notes="False positive verified")
        self.assertTrue(res2["success"])
        self.assertEqual(state["incidents"][0]["status"], "Dismissed")
        self.assertIn("198.51.100.90", state["dismissed_ips"])

    # -------------------------------------------------------------
    # Test 22: Audit logging integrity
    # -------------------------------------------------------------
    def test_22_audit_logging(self):
        """Test 22: Audit log records distinguish SUCCESS, REJECTED, and RELEASED with required fields."""
        state = {
            "incidents": [
                {"incident_id": "INC-0105", "src_ip": "198.51.100.95", "status": "New", "predicted_threat": "DoS/DDoS", "risk_score": 85.0, "severity": "Critical"},
                {"incident_id": "INC-0106", "src_ip": "10.0.0.1", "status": "New", "predicted_threat": "DoS/DDoS", "risk_score": 85.0, "severity": "Critical"}
            ],
            "blocklist": {},
            "audit_logs": [],
            "dismissed_ips": set()
        }
        # 1. Successful quarantine
        update_incident_status(state, "INC-0105", "Mitigated", actor="Admin")
        # 2. Rejected quarantine
        update_incident_status(state, "INC-0106", "Mitigated", actor="Admin")
        # 3. Manual release
        release_quarantined_ip(state, "198.51.100.95", actor="Admin")

        results = [log["result"] for log in state["audit_logs"]]
        self.assertIn("SUCCESS", results)
        self.assertIn("REJECTED", results)
        self.assertIn("RELEASED", results)

        required_fields = ["timestamp", "action", "target", "actor", "reason", "result"]
        for log in state["audit_logs"]:
            for field in required_fields:
                self.assertIn(field, log)
                self.assertTrue(len(str(log[field])) > 0, f"Field {field} must not be empty")

    # -------------------------------------------------------------
    # Test 23: JSON state persistence
    # -------------------------------------------------------------
    def test_23_json_persistence(self):
        """Test 23: StateStore atomically saves and reloads state accurately."""
        test_state_file = os.path.join(BASE_DIR, "data", "test_state_persist.json")
        store = StateStore(test_state_file)
        payload = {
            "blocklist": {"198.51.100.99": {"threat": "DDoS", "status": "BLOCKED"}},
            "audit_logs": [{"action": "BLOCK", "target": "198.51.100.99", "result": "SUCCESS"}],
            "total_flows_processed": 105,
            "blocked_traffic_drops": 7
        }
        self.assertTrue(store.save_state(payload))
        loaded = store.load_state()
        self.assertIn("198.51.100.99", loaded["blocklist"])
        self.assertEqual(loaded["total_flows_processed"], 105)
        self.assertEqual(loaded["blocked_traffic_drops"], 7)
        store.clear_state()

    # -------------------------------------------------------------
    # Test 24: Missing model files graceful error handling
    # -------------------------------------------------------------
    def test_24_missing_model_files_graceful_error(self):
        """Test 24: System gracefully detects missing model artifacts without unhandled exceptions."""
        is_valid, msg = inference.validate_artifacts()
        self.assertTrue(is_valid, f"Artifact health check failed: {msg}")

        original_rf_path = inference.RF_MODEL_PATH
        try:
            inference.RF_MODEL_PATH = os.path.join(BASE_DIR, "models", "missing_nonexistent_model.joblib")
            missing_valid, missing_msg = inference.validate_artifacts()
            self.assertFalse(missing_valid)
            self.assertIn("Missing required artifact", missing_msg)
        finally:
            inference.RF_MODEL_PATH = original_rf_path

    # -------------------------------------------------------------
    # Test 25: Corrupted state recovery
    # -------------------------------------------------------------
    def test_25_corrupted_state_recovery(self):
        """Test 25: StateStore recovers from backup file (.bak) when primary JSON is corrupted."""
        test_state_file = os.path.join(BASE_DIR, "data", "test_corrupt_recovery.json")
        store = StateStore(test_state_file)
        valid_state = {
            "blocklist": {"198.51.100.100": {"threat": "Brute Force", "status": "BLOCKED"}},
            "audit_logs": [],
            "total_flows_processed": 50,
            "blocked_traffic_drops": 2
        }
        # First save creates main and backup on subsequent save
        store.save_state(valid_state)
        valid_state["total_flows_processed"] = 51
        store.save_state(valid_state)

        # Corrupt primary JSON
        with open(test_state_file, "w") as f:
            f.write("{ CORRUPT MALFORMED JSON DATA !!!")

        recovered = store.load_state()
        self.assertIn("198.51.100.100", recovered["blocklist"])
        self.assertGreaterEqual(recovered["total_flows_processed"], 50)
        store.clear_state()


if __name__ == "__main__":
    unittest.main()

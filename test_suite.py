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
from services.alert_service import update_incident_status, purge_expired_quarantines


class TestCyberThreatMitigationSystem(unittest.TestCase):

    def setUp(self):
        # Ensure model artifacts are loaded
        inference.load_all_artifacts()

    # -------------------------------------------------------------
    # Test 1: Normal traffic classification
    # -------------------------------------------------------------
    def test_01_normal_traffic_classification(self):
        """Test 1: Verify benign network flow is classified as Normal with Low risk."""
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
    # Test 2: Known attack classification
    # -------------------------------------------------------------
    def test_02_known_attack_classification(self):
        """Test 2: Verify high-rate volumetric attack flow is identified as an attack."""
        df_sample = pd.read_csv(os.path.join(BASE_DIR, "data", "unsw_nb15_sample.csv"))
        attack_sample = df_sample[df_sample["attack_cat"] == "DoS/DDoS"].iloc[0].to_dict()
        res = inference.analyze_event(attack_sample)
        self.assertIn(res["predicted_threat"], ["DoS/DDoS", "Port Scan", "Brute Force", "Botnet", "Exploits"])
        self.assertGreaterEqual(res["risk_score"], 30.0)
        self.assertGreater(res["confidence"], 0.0)

    # -------------------------------------------------------------
    # Test 3: Unknown attack / unseen categorical handling
    # -------------------------------------------------------------
    def test_03_unknown_categorical_handling(self):
        """Test 3: Verify unseen categorical values map to reserved code 0 without crashing."""
        flow = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.5",
            "proto": "nonexistent_custom_proto",
            "service": "shadow_broker_svc",
            "state": "CUSTOM_FLAG"
        }
        df_row, unseen = inference.prepare_feature_row(flow, return_unseen=True)
        self.assertEqual(df_row["proto_code"].iloc[0], 0.0)
        self.assertEqual(df_row["service_code"].iloc[0], 0.0)
        self.assertEqual(df_row["state_code"].iloc[0], 0.0)
        self.assertGreaterEqual(len(unseen), 3)

    # -------------------------------------------------------------
    # Test 4: Missing feature handling
    # -------------------------------------------------------------
    def test_04_missing_feature_handling(self):
        """Test 4: Verify missing flow telemetry defaults safely and flags data quality warning."""
        # Flow with NO flow telemetry at all
        sparse_flow = {"src_ip": "198.51.100.88"}
        res = inference.analyze_event(sparse_flow)
        self.assertIsNotNone(res.get("data_quality_warning"))
        self.assertLessEqual(res["confidence"], 0.45)
        self.assertGreaterEqual(res["risk_score"], 0.0)
        self.assertLessEqual(res["risk_score"], 100.0)

    # -------------------------------------------------------------
    # Test 5: Invalid dataset rejection
    # -------------------------------------------------------------
    def test_05_invalid_dataset_rejection(self):
        """Test 5: Verify validate_and_prepare_csv rejects non-flow or empty data."""
        # 1. Non-flow schema
        df_invalid = pd.DataFrame({
            "username": ["alice", "bob"],
            "department": ["hr", "finance"]
        })
        val = inference.validate_and_prepare_csv(df_invalid)
        self.assertFalse(val["valid"])
        self.assertIn("Invalid dataset schema", val["summary_message"])

        # 2. Empty DataFrame
        val_empty = inference.validate_and_prepare_csv(pd.DataFrame())
        self.assertFalse(val_empty["valid"])

    # -------------------------------------------------------------
    # Test 6: Risk score range (0-100)
    # -------------------------------------------------------------
    def test_06_risk_score_normalization_and_bounds(self):
        """Test 6: Verify risk scores strictly stay within [0.0, 100.0] and valid severity tiers."""
        extreme_flows = [
            {"rate": 1e6, "sbytes": 1e9, "failed_login_count": 1000},
            {"rate": 0.0, "sbytes": 0.0, "spkts": 0.0, "dur": 0.0},
            {"proto": "udp", "rate": 500.0, "sbytes": 20000.0}
        ]
        for flow in extreme_flows:
            res = inference.analyze_event(flow)
            self.assertGreaterEqual(res["risk_score"], 0.0)
            self.assertLessEqual(res["risk_score"], 100.0)
            self.assertIn(res["risk_level"], ["Low", "Medium", "High", "Critical"])

    # -------------------------------------------------------------
    # Test 7: Mitigation rule generation
    # -------------------------------------------------------------
    def test_07_mitigation_rule_generation(self):
        """Test 7: Verify generate_firewall_rule creates valid Netsh and PowerShell syntax."""
        target_ip = "198.51.100.45"
        rule = generate_firewall_rule(target_ip)
        self.assertTrue(rule["valid"])
        self.assertIn("netsh advfirewall firewall add rule", rule["netsh_command"])
        self.assertIn("New-NetFirewallRule", rule["powershell_command"])
        self.assertEqual(rule["target_ip"], target_ip)

    # -------------------------------------------------------------
    # Test 8: Protected IP rejection
    # -------------------------------------------------------------
    def test_08_protected_ip_rejection(self):
        """Test 8: Verify loopback, 0.0.0.0, broadcast, gateway 10.0.0.1, DNS 8.8.8.8 cannot be blocked."""
        protected_ips = ["127.0.0.1", "0.0.0.0", "255.255.255.255", "10.0.0.1", "8.8.8.8", "10.0.0.5"]
        for ip in protected_ips:
            safe, reason = is_safe_to_block_ip(ip)
            self.assertFalse(safe, f"Expected {ip} to be unsafe to block")
            rule_res = generate_firewall_rule(ip)
            self.assertFalse(rule_res["valid"], f"Expected rule generation to fail for {ip}")

    # -------------------------------------------------------------
    # Test 9: Expired quarantine removal
    # -------------------------------------------------------------
    def test_09_expired_quarantine_removal(self):
        """Test 9: Verify purge_expired_quarantines releases entries past 3600s TTL."""
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
        audit_logs = []
        released = purge_expired_quarantines(blocklist, audit_logs)
        self.assertIn("198.51.100.77", released)
        self.assertNotIn("198.51.100.77", blocklist)
        self.assertIn("198.51.100.88", blocklist)
        self.assertTrue(any(log["action"] == "QUARANTINE_EXPIRED" and log["target"] == "198.51.100.77" for log in audit_logs))

    # -------------------------------------------------------------
    # Test 10: Audit log integrity
    # -------------------------------------------------------------
    def test_10_audit_log_integrity(self):
        """Test 10: Verify audit trail entries contain required schema fields and non-empty values."""
        state = {
            "incidents": [
                {"incident_id": "INC-0001", "src_ip": "198.51.100.50", "status": "New", "predicted_threat": "DoS/DDoS", "risk_score": 85.0, "severity": "Critical"}
            ],
            "blocklist": {},
            "audit_logs": [],
            "dismissed_ips": set()
        }
        update_incident_status(state, "INC-0001", "Investigating", actor="SOC Lead", analyst_notes="Inspecting flow burst")
        self.assertGreaterEqual(len(state["audit_logs"]), 1)
        entry = state["audit_logs"][0]
        required_fields = ["timestamp", "action", "target", "actor", "reason", "result"]
        for field in required_fields:
            self.assertIn(field, entry)
            self.assertTrue(len(str(entry[field])) > 0, f"Field {field} must not be empty")

    # -------------------------------------------------------------
    # Test 11: Role permission enforcement
    # -------------------------------------------------------------
    def test_11_role_permission_enforcement(self):
        """Test 11: Verify admin has full control and analyst is restricted from critical operations."""
        # Admin capabilities
        self.assertTrue(has_permission("admin", "retrain_models"))
        self.assertTrue(has_permission("admin", "clear_demo_state"))
        self.assertTrue(has_permission("admin", "approve_quarantine"))
        self.assertFalse(has_permission("admin", "toggle_real_firewall")) # Safely disabled in demo mode

        # Analyst restrictions
        self.assertFalse(has_permission("analyst", "toggle_real_firewall"))
        self.assertFalse(has_permission("analyst", "retrain_models"))
        self.assertFalse(has_permission("analyst", "clear_demo_state"))
        self.assertTrue(has_permission("analyst", "approve_quarantine"))

        # Unauthenticated / guest restrictions
        self.assertFalse(has_permission("guest", "approve_quarantine"))

    # -------------------------------------------------------------
    # Test 12: Password hashing & verification
    # -------------------------------------------------------------
    def test_12_password_hashing_and_verification(self):
        """Test 12: Verify secure bcrypt password hashing and constant-time authentication verification."""
        raw_pw = "CapStone$ecure2026"
        hashed = hash_password(raw_pw)
        self.assertTrue(hashed.startswith("$2b$") or hashed.startswith("$scrypt$"))
        self.assertTrue(verify_password(raw_pw, hashed))
        self.assertFalse(verify_password("WrongPassword123", hashed))

        admin_auth = authenticate_user("admin", "admin123")
        self.assertIsNotNone(admin_auth)
        self.assertEqual(admin_auth["role"], "admin")

        bad_auth = authenticate_user("admin", "invalid_password")
        self.assertIsNone(bad_auth)

    # -------------------------------------------------------------
    # Test 13: Missing model files graceful error handling
    # -------------------------------------------------------------
    def test_13_missing_model_files_graceful_error_handling(self):
        """Test 13: Verify validate_artifacts detects missing files and analyze_event fails gracefully."""
        valid, msg = inference.validate_artifacts()
        self.assertTrue(valid, f"Artifact health check failed: {msg}")

        # If a non-existent path is checked, it gracefully returns False
        original_rf_path = inference.RF_MODEL_PATH
        try:
            inference.RF_MODEL_PATH = "models/nonexistent_model.joblib"
            is_valid, err_msg = inference.validate_artifacts()
            self.assertFalse(is_valid)
            self.assertIn("Missing required artifact", err_msg)
        finally:
            inference.RF_MODEL_PATH = original_rf_path

    # -------------------------------------------------------------
    # Test 14: SHAP explanation validity
    # -------------------------------------------------------------
    def test_14_shap_explanation_validity(self):
        """Test 14: Verify SHAP feature attribution produces valid contributions and expected base value."""
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
        self.assertIsInstance(shap_data.get("base_value", 0.0), (int, float))

    # -------------------------------------------------------------
    # Test 15: MITRE ATT&CK technique consistency (parent vs subtechnique)
    # -------------------------------------------------------------
    def test_15_mitre_attack_technique_consistency(self):
        """Test 15: Verify parent technique_id strictly matches the prefix of sub_technique."""
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

    # -------------------------------------------------------------
    # Test 16: Failed mitigation rejection (no false success recorded)
    # -------------------------------------------------------------
    def test_16_failed_mitigation_rejection(self):
        """Test 16: Verify mitigating a protected infrastructure IP is rejected and logged as REJECTED."""
        state = {
            "incidents": [
                {
                    "incident_id": "INC-0099",
                    "src_ip": "10.0.0.1", # Protected Gateway IP
                    "status": "New",
                    "predicted_threat": "DoS/DDoS",
                    "risk_score": 90.0,
                    "severity": "Critical"
                }
            ],
            "blocklist": {},
            "audit_logs": [],
            "dismissed_ips": set()
        }
        res = update_incident_status(state, "INC-0099", "Mitigated", actor="Analyst Bob")
        self.assertFalse(res["success"])
        self.assertIn("rejected", res.get("message", "").lower())
        # IP must NOT be in blocklist
        self.assertNotIn("10.0.0.1", state["blocklist"])
        # Audit log must record failure/rejection, NOT SUCCESS
        self.assertGreaterEqual(len(state["audit_logs"]), 1)
        latest_audit = state["audit_logs"][0]
        self.assertEqual(latest_audit["result"], "REJECTED")
        self.assertEqual(latest_audit["action"], "INCIDENT_MITIGATION_REJECTED")

    # -------------------------------------------------------------
    # Supplementary Test: Atomic State Persistence
    # -------------------------------------------------------------
    def test_supplementary_atomic_state_persistence(self):
        """Verify StateStore handles atomic writes and recovery from corrupt state."""
        test_state_file = os.path.join(BASE_DIR, "data", "test_state.json")
        store = StateStore(test_state_file)
        test_data = {
            "blocklist": {"198.51.100.99": {"threat": "DDoS", "status": "BLOCKED"}},
            "audit_logs": [{"action": "BLOCK", "target": "198.51.100.99"}],
            "total_flows_processed": 100,
            "blocked_traffic_drops": 5
        }
        self.assertTrue(store.save_state(test_data))
        loaded = store.load_state()
        self.assertIn("198.51.100.99", loaded["blocklist"])
        with open(test_state_file, "w") as f:
            f.write("{ CORRUPT DATA")
        recovered = store.load_state()
        self.assertIn("198.51.100.99", recovered["blocklist"])
        store.clear_state()


if __name__ == "__main__":
    unittest.main()

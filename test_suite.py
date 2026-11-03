import os
import sys
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
from services.auth_service import authenticate_user, has_permission
from services.mitigation_service import (
    validate_ip_address,
    is_safe_to_block_ip,
    generate_firewall_rule,
    check_ip_whitelist
)

class TestCyberThreatMitigationSystem(unittest.TestCase):

    def test_01_confusion_matrix_defensive_checks(self):
        """Finding E: Verify compute_per_class_metrics doesn't crash on missing classes."""
        classes = ["Botnet", "Brute Force", "DoS/DDoS", "Exploits", "Normal", "Port Scan"]
        # y_true only has Normal (4) and DoS/DDoS (2); other 4 classes are completely missing
        y_true = np.array([4, 4, 2, 4, 2])
        y_pred = np.array([4, 2, 2, 4, 4])
        
        # Must not raise IndexError
        metrics = compute_per_class_metrics(y_true, y_pred, classes)
        self.assertEqual(len(metrics), len(classes))
        for c in classes:
            self.assertIn(c, metrics)
            self.assertIn("precision", metrics[c])
            self.assertIn("recall", metrics[c])
            self.assertIn("f1_score", metrics[c])

    def test_02_unknown_categorical_handling(self):
        """Finding A: Verify unseen categories are mapped to code 0 and tracked."""
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

    def test_03_risk_score_normalization_and_bounds(self):
        """Finding B: Verify composite risk score is strictly normalized (0-100) and within tiers."""
        # Test extreme high risk attack
        high_threat_flow = {
            "src_ip": "45.33.32.156",
            "dst_ip": "10.0.0.5",
            "failed_login_count": 50,
            "connection_count": 5000,
            "unique_port_count": 100,
            "rate": 10000,
            "sbytes": 500000
        }
        res = inference.analyze_event(high_threat_flow)
        self.assertGreaterEqual(res["risk_score"], 0.0)
        self.assertLessEqual(res["risk_score"], 100.0)
        self.assertIn(res["risk_level"], ["Low", "Medium", "High", "Critical"])

        # Test normal flow
        normal_flow = {
            "src_ip": "192.168.1.45",
            "dst_ip": "10.0.0.5",
            "proto": "tcp",
            "service": "http",
            "state": "FIN",
            "rate": 10,
            "spkts": 10,
            "dpkts": 12,
            "sbytes": 500,
            "dbytes": 1000
        }
        res_normal = inference.analyze_event(normal_flow)
        self.assertGreaterEqual(res_normal["risk_score"], 0.0)
        self.assertLessEqual(res_normal["risk_score"], 100.0)

    def test_04_firewall_safety_safeguards(self):
        """Finding D: Verify that loopback, broadcast, 0.0.0.0, and whitelisted infrastructure cannot be blocked."""
        # 1. Loopback
        safe, reason = is_safe_to_block_ip("127.0.0.1")
        self.assertFalse(safe)
        self.assertIn("loopback", reason.lower())

        # 2. Unspecified
        safe, reason = is_safe_to_block_ip("0.0.0.0")
        self.assertFalse(safe)
        self.assertIn("unspecified", reason.lower())

        # 3. Broadcast
        safe, reason = is_safe_to_block_ip("255.255.255.255")
        self.assertFalse(safe)
        self.assertIn("broadcast", reason.lower())

        # 4. Critical Infrastructure (Perimeter Gateway & DNS)
        safe, reason = is_safe_to_block_ip("10.0.0.1")
        self.assertFalse(safe)
        self.assertIn("protected", reason.lower())

        safe, reason = is_safe_to_block_ip("8.8.8.8")
        self.assertFalse(safe)

        # 5. External Malicious IP should be safe to block
        safe, reason = is_safe_to_block_ip("198.51.100.45")
        self.assertTrue(safe)

        # 6. Rule generation for unsafe IP must return valid: False
        rule_res = generate_firewall_rule("127.0.0.1")
        self.assertFalse(rule_res["valid"])

    def test_05_atomic_state_persistence(self):
        """Finding B: Verify StateStore handles atomic writes and .bak recovery."""
        test_state_file = os.path.join(BASE_DIR, "data", "test_state.json")
        store = StateStore(test_state_file)
        
        # Save valid state
        test_data = {
            "blocklist": {"198.51.100.99": {"threat": "DDoS", "status": "BLOCKED"}},
            "audit_logs": [{"action": "BLOCK", "target": "198.51.100.99"}],
            "total_flows_processed": 100,
            "blocked_traffic_drops": 5
        }
        save_ok = store.save_state(test_data)
        self.assertTrue(save_ok)
        self.assertTrue(os.path.exists(test_state_file))

        # Load state
        loaded = store.load_state()
        self.assertIn("198.51.100.99", loaded["blocklist"])
        self.assertEqual(loaded["total_flows_processed"], 100)

        # Simulate primary file corruption
        with open(test_state_file, "w") as f:
            f.write("{ INVALID CORRUPTED JSON")

        # Load should recover from .bak
        recovered = store.load_state()
        self.assertIn("198.51.100.99", recovered["blocklist"])

        # Clean up
        store.clear_state()
        self.assertFalse(os.path.exists(test_state_file))

    def test_06_authentication_and_rbac(self):
        """Finding D: Verify authentication, password hashing, and role permission boundaries."""
        # 1. Admin login
        admin_user = authenticate_user("admin", "admin123")
        self.assertIsNotNone(admin_user)
        self.assertEqual(admin_user["role"], "admin")
        self.assertTrue(has_permission(admin_user["role"], "toggle_real_firewall"))
        self.assertTrue(has_permission(admin_user["role"], "retrain_models"))
        self.assertTrue(has_permission(admin_user["role"], "clear_demo_state"))

        # 2. Analyst login
        analyst_user = authenticate_user("analyst", "analyst123")
        self.assertIsNotNone(analyst_user)
        self.assertEqual(analyst_user["role"], "analyst")
        self.assertFalse(has_permission(analyst_user["role"], "toggle_real_firewall"))
        self.assertFalse(has_permission(analyst_user["role"], "retrain_models"))
        self.assertFalse(has_permission(analyst_user["role"], "clear_demo_state"))
        self.assertTrue(has_permission(analyst_user["role"], "approve_quarantine"))

        # 3. Bad credentials
        bad_user = authenticate_user("admin", "wrong_password")
        self.assertIsNone(bad_user)

    def test_07_artifact_health_validation(self):
        """Finding C: Verify validate_artifacts checks artifact consistency."""
        valid, msg = inference.validate_artifacts()
        self.assertTrue(valid, f"Artifact validation failed: {msg}")

    def test_08_csv_schema_validation(self):
        """Verify CSV schema validator checks columns, data types, missing values, and unseen categories."""
        df_sample = pd.DataFrame({
            "duration": [0.05, 1.2],
            "packets_sent": [10, 50],
            "packets_recv": [8, 40],
            "bytes_sent": [400, 2000],
            "bytes_received": [800, 4000],
            "rate": ["150.5", "invalid_numeric"],
            "proto": ["tcp", "wireguard_custom"],
            "service": ["http", "unknown_custom_service"],
            "state": ["FIN", "NEW_STATE"]
        })
        val = inference.validate_and_prepare_csv(df_sample)
        self.assertTrue(val["valid"])
        self.assertEqual(val["total_rows"], 2)
        self.assertIn("proto", val["unseen_categories"])
        self.assertIn("wireguard_custom", val["unseen_categories"]["proto"])
        self.assertIn("service", val["unseen_categories"])
        self.assertGreaterEqual(val["coerced_nan_count"], 1)

    def test_09_incident_lifecycle_transitions(self):
        """Verify Incident lifecycle state updates: New -> Investigating -> Mitigated -> Dismissed."""
        from services.alert_service import update_incident_status
        state = {
            "incidents": [
                {
                    "incident_id": "INC-0001",
                    "src_ip": "198.51.100.77",
                    "status": "New",
                    "predicted_threat": "DoS/DDoS",
                    "risk_score": 85.0,
                    "severity": "Critical"
                }
            ],
            "blocklist": {},
            "audit_logs": [],
            "dismissed_ips": set()
        }

        # 1. Transition New -> Investigating
        res1 = update_incident_status(state, "INC-0001", "Investigating", analyst_notes="Triaging flow vectors")
        self.assertTrue(res1["success"])
        self.assertEqual(state["incidents"][0]["status"], "Investigating")

        # 2. Transition Investigating -> Mitigated (Simulates quarantine)
        res2 = update_incident_status(state, "INC-0001", "Mitigated", analyst_notes="Confirmed DDoS flooding")
        self.assertTrue(res2["success"])
        self.assertEqual(state["incidents"][0]["status"], "Mitigated")
        self.assertIn("198.51.100.77", state["blocklist"])
        self.assertEqual(state["incidents"][0]["mitigation_status"], "SIMULATED QUARANTINED")

        # 3. Transition Mitigated -> Dismissed (Simulates release)
        res3 = update_incident_status(state, "INC-0001", "Dismissed", analyst_notes="False positive verified")
        self.assertTrue(res3["success"])
        self.assertEqual(state["incidents"][0]["status"], "Dismissed")
        self.assertNotIn("198.51.100.77", state["blocklist"])
        self.assertIn("198.51.100.77", state["dismissed_ips"])

    def test_10_simulated_mitigation_safe_mode(self):
        """Verify simulated mitigation operates 100% in software state without OS modification."""
        from services.mitigation_service import execute_firewall_rule, remove_firewall_rule
        # Execution
        exec_res = execute_firewall_rule("198.51.100.123", simulate_safe=True)
        self.assertTrue(exec_res["success"])
        self.assertTrue(exec_res["simulated"])
        self.assertIn("Simulated", exec_res["mode"])

        # Rollback
        rem_res = remove_firewall_rule("198.51.100.123", simulate_safe=True)
        self.assertTrue(rem_res["success"])
        self.assertTrue(rem_res["simulated"])
        self.assertIn("Simulated", rem_res["mode"])

if __name__ == "__main__":
    unittest.main()


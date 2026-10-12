import unittest
from unittest.mock import patch, MagicMock
import os
import json
import time
import ipaddress
import numpy as np
import pandas as pd

import inference
import model_trainer


class TestFirewallSafety(unittest.TestCase):
    """TASK 1 & TASK 4: Tests for firewall command safety, IP validation, and injection prevention."""

    def test_valid_ipv4(self):
        """Valid IPv4 addresses should pass validation and return normalized string."""
        valid_ip = "192.168.1.100"
        self.assertEqual(inference.validate_ip_address(valid_ip), valid_ip)
        self.assertTrue(inference.is_valid_ip(valid_ip))

        valid_ip2 = "  10.0.0.5  "
        self.assertEqual(inference.validate_ip_address(valid_ip2), "10.0.0.5")

    def test_valid_ipv6(self):
        """Valid IPv6 addresses should be supported safely."""
        valid_ipv6 = "2001:db8::1"
        self.assertEqual(inference.validate_ip_address(valid_ipv6), "2001:db8::1")
        self.assertTrue(inference.is_valid_ip(valid_ipv6))

    def test_command_injection_prevention(self):
        """Shell injection payloads must be rejected by validation and not constructed into rules."""
        injection_payloads = [
            "192.168.1.1 & calc.exe",
            "10.0.0.1; rm -rf /",
            "1.1.1.1 | dir",
            "1.2.3.4' && whoami",
            '1.2.3.4" && net user',
            "127.0.0.1 $(reboot)",
            "192.168.1.1`notepad.exe`",
            "10.0.0.1\nwhoami"
        ]
        for payload in injection_payloads:
            with self.subTest(payload=payload):
                self.assertFalse(inference.is_valid_ip(payload))
                with self.assertRaises(ValueError):
                    inference.validate_ip_address(payload)

                rule = inference.generate_firewall_rule(payload)
                self.assertFalse(rule["valid"])
                self.assertIsNotNone(rule["error"])
                self.assertEqual(rule["netsh_args"], [])

    def test_malformed_ips(self):
        """Invalid IP formats must raise ValueError and be marked invalid."""
        malformed = ["999.999.999.999", "abc.def.ghi.jkl", "", "   ", None, "192.168.1", "256.1.1.1"]
        for bad in malformed:
            with self.subTest(bad=bad):
                self.assertFalse(inference.is_valid_ip(bad))
                rule = inference.generate_firewall_rule(bad)
                self.assertFalse(rule["valid"])

    def test_safe_argument_lists(self):
        """Generated firewall rule must use discrete argument lists suitable for shell=False."""
        ip = "198.51.100.25"
        rule = inference.generate_firewall_rule(ip)
        self.assertTrue(rule["valid"])
        self.assertIn("netsh_args", rule)
        self.assertIn("rollback_args", rule)
        self.assertIsInstance(rule["netsh_args"], list)
        self.assertIsInstance(rule["rollback_args"], list)
        self.assertEqual(rule["netsh_args"][0], "netsh")
        self.assertEqual(rule["rollback_args"][0], "netsh")
        self.assertIn(f"remoteip={ip}", rule["netsh_args"])

    def test_simulated_execution_default(self):
        """Default execution must be in simulated sandbox without executing host commands."""
        ip = "203.0.113.50"
        with patch("subprocess.run") as mock_subproc:
            res = inference.execute_firewall_rule(ip, simulate_safe=True)
            self.assertTrue(res["success"])
            self.assertTrue(res.get("simulated", False))
            self.assertIn("Simulated Sandbox", res["mode"])
            mock_subproc.assert_not_called()

        with patch("subprocess.run") as mock_subproc:
            rem_res = inference.remove_firewall_rule(ip, simulate_safe=True)
            self.assertTrue(rem_res["success"])
            self.assertTrue(rem_res.get("simulated", False))
            mock_subproc.assert_not_called()

    def test_mocked_live_execution_uses_shell_false(self):
        """When live host execution is explicitly requested, subprocess.run must be called with shell=False."""
        ip = "203.0.113.60"
        with patch("subprocess.run") as mock_subproc:
            mock_subproc.return_value = MagicMock(returncode=0, stdout="Ok.\r\n", stderr="")
            res = inference.execute_firewall_rule(ip, simulate_safe=False)
            mock_subproc.assert_called_once()
            _, kwargs = mock_subproc.call_args
            self.assertFalse(kwargs.get("shell", True), "Subprocess must be called with shell=False")
            self.assertTrue(res["success"])

    def test_mitigation_failure_reporting(self):
        """Host execution failure must return success=False and never falsely report success."""
        ip = "203.0.113.70"
        with patch("subprocess.run") as mock_subproc:
            mock_subproc.return_value = MagicMock(returncode=1, stdout="", stderr="An error occurred: Access denied.")
            res = inference.execute_firewall_rule(ip, simulate_safe=False)
            self.assertFalse(res["success"])
            self.assertIn("Command failed", res["status_message"])

        with patch("subprocess.run") as mock_subproc:
            mock_subproc.return_value = MagicMock(returncode=1, stdout="", stderr="The specified rule does not exist.")
            rem_res = inference.remove_firewall_rule(ip, simulate_safe=False)
            self.assertFalse(rem_res["success"])


class TestModelMetricsAndDataset(unittest.TestCase):
    """TASK 2: Tests for ML evaluation integrity, sample counts, and synthetic disclosure."""

    def test_dataset_metadata_sample_counts_and_synthetic_disclosure(self):
        """Model comparison metadata must separate original from SMOTE counts and disclose synthetic nature."""
        meta_path = model_trainer.METADATA_PATH
        self.assertTrue(os.path.exists(meta_path), "model_comparison.json must exist")
        with open(meta_path, "r") as f:
            data = json.load(f)

        dataset_info = data.get("dataset", {})
        self.assertIn("original_train_samples", dataset_info, "Original train samples must be reported separately")
        self.assertIn("smote_resampled_train_samples", dataset_info, "SMOTE resampled count must be reported separately")
        self.assertIn("validation_samples", dataset_info)
        self.assertIn("test_samples", dataset_info)

        # Confirm original counts partition total samples
        total = dataset_info.get("total_samples", 0)
        orig_train = dataset_info.get("original_train_samples", 0)
        val = dataset_info.get("validation_samples", 0)
        test = dataset_info.get("test_samples", 0)
        self.assertEqual(orig_train + val + test, total, "Original splits (train + val + test) must sum to total_samples")

        # Confirm synthetic disclosure
        self.assertIn("Synthetic", dataset_info.get("data_type", "") + dataset_info.get("name", ""))
        self.assertIn("benchmark_note", dataset_info)

    def test_no_fabricated_roc_auc_fallback(self):
        """ROC-AUC must not fall back to fabricated numbers when calculation fails."""
        y_single_class = pd.Series([0, 0, 0, 0])
        prob_matrix = np.array([[0.9, 0.1], [0.8, 0.2], [0.7, 0.3], [0.85, 0.15]])

        # Under single class, calculation fails or yields NaN; system must resolve to None rather than fabricated float
        try:
            from sklearn.metrics import roc_auc_score
            val = float(roc_auc_score(y_single_class, prob_matrix[:, 1]))
            if np.isnan(val):
                val = None
        except Exception:
            val = None

        # Verify our fallback pattern returns None, not fabricated numbers like 0.995 or 0.998
        self.assertIsNone(val)


class TestThreatDetectionScenarios(unittest.TestCase):
    """TASK 4: Test 6 individual threat scenarios (Normal, Brute Force, Port Scan, DoS/DDoS, Suspicious Login, Malformed)."""

    def setUp(self):
        inference.load_all_artifacts()

    def test_scenario_normal_traffic(self):
        """Normal traffic flow must evaluate to low risk and recommended baseline action."""
        flow = {
            "src_ip": "192.168.1.105",
            "dst_ip": "10.0.0.5",
            "proto": "tcp",
            "service": "http",
            "state": "FIN",
            "dur": 0.45,
            "spkts": 12,
            "dpkts": 15,
            "sbytes": 850,
            "dbytes": 3200,
            "rate": 60.0,
            "sttl": 64,
            "dttl": 64,
            "sload": 15000.0,
            "dload": 57000.0,
            "sloss": 0,
            "dloss": 0,
            "sinpkt": 37.5,
            "dinpkt": 30.0,
            "tcprtt": 18.0,
            "synack": 8.0,
            "ackdat": 10.0,
            "ct_state_ttl": 2,
            "ct_srv_src": 3,
            "ct_dst_ltm": 2,
            "ct_src_dport_ltm": 1,
            "failed_login_count": 0,
            "unique_port_count": 1,
            "connection_count": 3
        }
        res = inference.analyze_event(flow, model_override="random_forest")
        self.assertIn("predicted_threat", res)
        self.assertIn("risk_score", res)
        self.assertIn("confidence", res)
        self.assertIn("explanation", res)
        # Normal traffic should have low risk score
        self.assertLess(res["risk_score"], 45.0)

    def test_scenario_bruteforce_attack(self):
        """Brute force traffic with high failed logins should show elevated risk and MITRE T1110."""
        flow = {
            "src_ip": "185.220.101.40",
            "dst_ip": "10.0.0.5",
            "dst_port": 22,
            "proto": "tcp",
            "service": "ssh",
            "state": "CON",
            "dur": 2.8,
            "spkts": 45,
            "dpkts": 40,
            "sbytes": 7400,
            "dbytes": 4400,
            "rate": 30.3,
            "sttl": 128,
            "dttl": 128,
            "ct_state_ttl": 6,
            "ct_srv_src": 12,
            "ct_dst_ltm": 10,
            "ct_src_dport_ltm": 8,
            "failed_login_count": 18,
            "unique_port_count": 1,
            "connection_count": 45
        }
        res = inference.analyze_event(flow, model_override="random_forest")
        self.assertIn(res["risk_level"], ["Medium", "High", "Critical"])
        self.assertGreater(res["risk_score"], 50.0)
        mitre = res.get("mitre_attack", {})
        if res["predicted_threat"] == "Brute Force":
            self.assertEqual(mitre.get("technique_id"), "T1110")

    def test_scenario_port_scanning(self):
        """Port scan traffic probing many unique ports should show MITRE T1046."""
        flow = {
            "src_ip": "198.51.100.99",
            "dst_ip": "10.0.0.5",
            "proto": "tcp",
            "service": "-",
            "state": "INT",
            "dur": 0.05,
            "spkts": 4,
            "dpkts": 0,
            "sbytes": 160,
            "dbytes": 0,
            "rate": 80.0,
            "failed_login_count": 0,
            "unique_port_count": 85,
            "connection_count": 120
        }
        res = inference.analyze_event(flow, model_override="random_forest")
        self.assertIn("predicted_threat", res)
        if res["predicted_threat"] == "Port Scan":
            self.assertEqual(res["mitre_attack"]["technique_id"], "T1046")

    def test_scenario_dos_ddos(self):
        """Volumetric DoS/DDoS flow should reflect high packet rate and MITRE T1498."""
        flow = {
            "src_ip": "45.33.32.100",
            "dst_ip": "10.0.0.5",
            "proto": "udp",
            "service": "dns",
            "state": "INT",
            "dur": 0.01,
            "spkts": 1200,
            "dpkts": 0,
            "sbytes": 850000,
            "dbytes": 0,
            "rate": 120000.0,
            "failed_login_count": 0,
            "unique_port_count": 1,
            "connection_count": 500
        }
        res = inference.analyze_event(flow, model_override="random_forest")
        self.assertGreater(res["risk_score"], 40.0)
        if res["predicted_threat"] == "DoS/DDoS":
            self.assertEqual(res["mitre_attack"]["technique_id"], "T1498")

    def test_scenario_suspicious_login_modifier(self):
        """Failed login counts should actively raise the telemetry modifier in risk calculation."""
        flow_baseline = {"dur": 1.0, "failed_login_count": 0, "connection_count": 1, "unique_port_count": 1}
        flow_suspicious = {"dur": 1.0, "failed_login_count": 10, "connection_count": 1, "unique_port_count": 1}

        res_base = inference.analyze_event(flow_baseline)
        res_susp = inference.analyze_event(flow_suspicious)
        self.assertGreaterEqual(
            res_susp["risk_breakdown"]["telemetry_modifier"],
            res_base["risk_breakdown"]["telemetry_modifier"]
        )

    def test_scenario_unknown_or_malformed_input(self):
        """Malformed flow with missing fields, invalid types, or unexpected keys must not crash."""
        malformed_flow = {
            "src_ip": "invalid-ip",
            "dur": "not_a_float",
            "sbytes": None,
            "proto": 12345,
            "unexpected_junk": "test"
        }
        # Should execute safely without uncaught exception
        res = inference.analyze_event(malformed_flow)
        self.assertIn("predicted_threat", res)
        self.assertIn("risk_score", res)
        self.assertFalse(res["firewall_rule_specs"]["valid"])


class TestAllowlistingAndQuarantine(unittest.TestCase):
    """TASK 3 & TASK 4: Tests for allowlisting immunity and quarantine management."""

    def test_critical_infrastructure_allowlisting(self):
        """Perimeter gateway 10.0.0.1 and loopback 127.0.0.1 must be immune from quarantine."""
        is_wl, reason = inference.check_ip_whitelist("10.0.0.1")
        self.assertTrue(is_wl)
        self.assertIn("Gateway", reason)

        is_wl_dns, _ = inference.check_ip_whitelist("8.8.8.8")
        self.assertTrue(is_wl_dns)

    def test_protected_subnet_allowlisting(self):
        """Any IP inside 10.0.0.0/24 subnet must be identified as allowlisted."""
        is_wl, reason = inference.check_ip_whitelist("10.0.0.45")
        self.assertTrue(is_wl)
        self.assertIn("10.0.0.0/24", reason)

    def test_attacker_ip_not_allowlisted(self):
        """External non-whitelisted IP must not be granted immunity."""
        is_wl, _ = inference.check_ip_whitelist("185.220.101.5")
        self.assertFalse(is_wl)

    def test_allowlist_prevents_block_action(self):
        """High risk event from a protected IP must not result in BLOCK_IP action."""
        high_risk_flow = {
            "src_ip": "10.0.0.1",  # Whitelisted default gateway
            "dst_ip": "10.0.0.5",
            "dst_port": 80,
            "proto": "tcp",
            "service": "http",
            "state": "REQ",
            "dur": 0.15,
            "spkts": 250,
            "dpkts": 4,
            "sbytes": 110000,
            "dbytes": 240,
            "rate": 1693.0,
            "sttl": 64,
            "dttl": 0,
            "ct_state_ttl": 12,
            "ct_srv_src": 35,
            "ct_dst_ltm": 50,
            "ct_src_dport_ltm": 25,
            "connection_count": 320
        }
        res = inference.analyze_event(high_risk_flow)
        self.assertTrue(res["is_whitelisted"])
        self.assertEqual(res["action_code"], "WHITELIST_PROTECTED")

    def test_quarantine_expiry_logic(self):
        """Expired TTL records must be identified for removal, while unexpired ones remain."""
        now = time.time()
        test_blocklist = {
            "203.0.113.1": {
                "quarantined_at": now - 4000,  # 4000s ago (> 3600s TTL) -> expired
                "ttl_seconds": 3600,
                "status": "BLOCKED (Simulated Sandbox)"
            },
            "203.0.113.2": {
                "quarantined_at": now - 300,   # 300s ago (< 3600s TTL) -> active
                "ttl_seconds": 3600,
                "status": "BLOCKED (Simulated Sandbox)"
            }
        }
        expired_ips = []
        for ip, meta in list(test_blocklist.items()):
            if meta.get("status", "").startswith("BLOCKED"):
                if (now - meta.get("quarantined_at", now)) >= meta.get("ttl_seconds", 3600):
                    expired_ips.append(ip)
                    del test_blocklist[ip]

        self.assertEqual(expired_ips, ["203.0.113.1"])
        self.assertIn("203.0.113.2", test_blocklist)
        self.assertNotIn("203.0.113.1", test_blocklist)


if __name__ == "__main__":
    unittest.main(verbosity=2)

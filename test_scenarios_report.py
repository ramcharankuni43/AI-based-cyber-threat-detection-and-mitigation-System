import inference
import pandas as pd
import json

# Representative realistic test flows for each scenario
scenarios = [
    ("Normal traffic", {
        "src_ip": "192.168.1.105", "dst_ip": "10.0.0.5", "proto": "tcp", "service": "http", "state": "FIN",
        "dur": 0.85, "spkts": 18, "dpkts": 22, "sbytes": 4500, "dbytes": 12800, "rate": 47.0,
        "sttl": 64, "dttl": 64, "sload": 42000.0, "dload": 120000.0, "sloss": 0, "dloss": 0,
        "sinpkt": 44.0, "dinpkt": 36.0, "tcprtt": 28.0, "synack": 12.6, "ackdat": 15.4,
        "ct_state_ttl": 2, "ct_srv_src": 4, "ct_dst_ltm": 3, "ct_src_dport_ltm": 1,
        "failed_login_count": 0, "unique_port_count": 1, "connection_count": 2
    }),
    ("Brute-force attack", {
        "src_ip": "185.220.101.40", "dst_ip": "10.0.0.5", "dst_port": 22, "proto": "tcp", "service": "ssh", "state": "CON",
        "dur": 2.8, "spkts": 45, "dpkts": 40, "sbytes": 7400, "dbytes": 4400, "rate": 30.3,
        "sttl": 128, "dttl": 128, "sload": 21000.0, "dload": 12500.0, "sloss": 1, "dloss": 0,
        "sinpkt": 60.0, "dinpkt": 68.0, "tcprtt": 26.0, "synack": 13.0, "ackdat": 13.0,
        "ct_state_ttl": 6, "ct_srv_src": 12, "ct_dst_ltm": 10, "ct_src_dport_ltm": 8,
        "failed_login_count": 18, "unique_port_count": 1, "connection_count": 45
    }),
    ("Port scanning", {
        "src_ip": "198.51.100.25", "dst_ip": "10.0.0.12", "proto": "tcp", "service": "-", "state": "INT",
        "dur": 0.08, "spkts": 4, "dpkts": 0, "sbytes": 180, "dbytes": 0, "rate": 50.0,
        "sttl": 64, "dttl": 0, "sload": 18000.0, "dload": 0.0, "sloss": 0, "dloss": 0,
        "sinpkt": 20.0, "dinpkt": 0.0, "tcprtt": 0.0, "synack": 0.0, "ackdat": 0.0,
        "ct_state_ttl": 8, "ct_srv_src": 15, "ct_dst_ltm": 22, "ct_src_dport_ltm": 3,
        "failed_login_count": 0, "unique_port_count": 45, "connection_count": 60
    }),
    ("DoS/DDoS traffic", {
        "src_ip": "45.33.32.88", "dst_ip": "10.0.0.5", "dst_port": 80, "proto": "tcp", "service": "http", "state": "REQ",
        "dur": 0.15, "spkts": 250, "dpkts": 4, "sbytes": 110000, "dbytes": 240, "rate": 1693.0,
        "sttl": 64, "dttl": 0, "sload": 5860000.0, "dload": 12800.0, "sloss": 25, "dloss": 0,
        "sinpkt": 0.6, "dinpkt": 30.0, "tcprtt": 65.0, "synack": 39.0, "ackdat": 26.0,
        "ct_state_ttl": 12, "ct_srv_src": 35, "ct_dst_ltm": 50, "ct_src_dport_ltm": 25,
        "failed_login_count": 0, "unique_port_count": 1, "connection_count": 320
    }),
    ("Suspicious login", {
        "src_ip": "192.168.1.180", "dst_ip": "10.0.0.5", "dst_port": 22, "proto": "tcp", "service": "ssh", "state": "CON",
        "dur": 1.5, "spkts": 25, "dpkts": 20, "sbytes": 3800, "dbytes": 2200, "rate": 30.0,
        "sttl": 64, "dttl": 64, "sload": 20000.0, "dload": 11000.0, "sloss": 0, "dloss": 0,
        "sinpkt": 57.0, "dinpkt": 71.0, "tcprtt": 25.0, "synack": 12.0, "ackdat": 13.0,
        "ct_state_ttl": 3, "ct_srv_src": 4, "ct_dst_ltm": 4, "ct_src_dport_ltm": 2,
        "failed_login_count": 7, "unique_port_count": 1, "connection_count": 8
    }),
    ("Unknown or malformed input", {
        "src_ip": "invalid-ip-string", "dst_ip": "unknown-host", "proto": "unknown_proto", "service": "bad_svc", "state": "XYZ",
        "dur": "bad_dur", "spkts": "invalid", "sbytes": None, "connection_count": -99
    })
]

print("\n" + "=" * 95)
print("THREAT DETECTION VERIFICATION MATRIX (SCENARIOS 1-6)")
print("=" * 95)
print(f"{'Scenario':<28} | {'Predicted Threat':<17} | {'Confidence':<10} | {'Risk':<6} | {'Level':<8} | {'MITRE':<8}")
print("-" * 95)

results = []
for name, flow in scenarios:
    res = inference.analyze_event(flow, model_override="random_forest")
    pred = res["predicted_threat"]
    conf = f"{res['confidence'] * 100:.1f}%"
    risk = f"{res['risk_score']:.1f}"
    lvl = res["risk_level"]
    mitre = res.get("mitre_attack", {}).get("technique_id", "None")
    print(f"{name:<28} | {pred:<17} | {conf:<10} | {risk:<6} | {lvl:<8} | {mitre:<8}")
    print(f"   Action: {res['recommended_action']}")
    print(f"   Rationale: {res['explanation'].strip()}")
    print("-" * 95)
    results.append({
        "scenario": name,
        "predicted_threat": pred,
        "confidence": conf,
        "risk_score": risk,
        "risk_level": lvl,
        "mitre_id": mitre,
        "action": res["recommended_action"]
    })

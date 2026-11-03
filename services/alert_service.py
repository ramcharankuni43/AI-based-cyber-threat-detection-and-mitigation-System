import time
import pandas as pd
from services.mitigation_service import execute_firewall_rule, remove_firewall_rule

def purge_expired_quarantines(blocklist: dict, audit_logs: list, enforcement_backend: str) -> list[str]:
    """
    Evaluates 1-hour TTL leases for quarantined IPs and safely releases expired entries.
    Returns list of released IPs.
    """
    now = time.time()
    expired_ips = []
    
    for ip, meta in list(blocklist.items()):
        if meta.get("status", "").startswith("BLOCKED"):
            quarantined_at = meta.get("quarantined_at", now)
            ttl = meta.get("ttl_seconds", 3600)
            if (now - quarantined_at) >= ttl:
                expired_ips.append(ip)

    backend_is_real = enforcement_backend.startswith("Windows Defender")

    for ip in expired_ips:
        if backend_is_real:
            rem_res = remove_firewall_rule(ip, simulate_safe=False)
            if rem_res.get("success", False):
                del blocklist[ip]
                audit_logs.insert(0, {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "action": "QUARANTINE_EXPIRED",
                    "target": ip,
                    "actor": "TTL Decay Daemon (Real Host Netsh)",
                    "reason": "1-Hour lease expired. Host OS firewall rule removed and verified.",
                    "result": "SUCCESS"
                })
            else:
                audit_logs.insert(0, {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "action": "QUARANTINE_EXPIRY_ERROR",
                    "target": ip,
                    "actor": "TTL Decay Daemon (Real Host Netsh)",
                    "reason": f"1-Hour lease expired but OS firewall removal failed: {rem_res.get('status_message')}",
                    "result": "FAILURE"
                })
        else:
            remove_firewall_rule(ip, simulate_safe=True)
            del blocklist[ip]
            audit_logs.insert(0, {
                "timestamp": time.strftime("%H:%M:%S"),
                "action": "QUARANTINE_EXPIRED",
                "target": ip,
                "actor": "TTL Decay Daemon (Simulated Sandbox)",
                "reason": "1-Hour lease expired. IP released from simulated blocklist.",
                "result": "SUCCESS"
            })

    return expired_ips

def process_stream_batch(
    batch_df: pd.DataFrame,
    batch_label: str,
    source_type: str,
    state: dict,
    inference_module
) -> None:
    """
    Centralized telemetry stream ingestion engine:
    1. Evaluates incoming flow vectors against active firewall blocklist.
    2. Runs multi-class AI inference and anomaly scoring.
    3. Executes automated mitigation or queues for analyst approval.
    4. Records compliance audit trail.
    """
    blocklist = state["blocklist"]
    audit_logs = state["audit_logs"]
    alerts_history = state["alerts_history"]
    dismissed_ips = state["dismissed_ips"]
    mitigation_mode = state.get("mitigation_mode", "Autonomous Auto-Block")
    enforcement_backend = state.get("enforcement_backend", "Simulated Sandbox (Safe Lab)")

    backend_is_real = enforcement_backend.startswith("Windows Defender")

    for _, row in batch_df.iterrows():
        flow = row.to_dict()
        src_ip = str(flow.get("src_ip", "")).strip()

        is_already_blocked = (src_ip in blocklist and blocklist[src_ip]["status"].startswith("BLOCKED"))

        if is_already_blocked:
            state["blocked_traffic_drops"] += 1
            firewall_status = "DROPPED (Firewall Active)"
        else:
            firewall_status = "PENDING_EVALUATION"

        res = inference_module.analyze_event(flow, model_override="random_forest")
        action_code = res.get("action_code", "LOG_ONLY")
        risk_lvl = res.get("risk_level", "Low")

        # Mitigation decision flow
        if firewall_status.startswith("DROPPED"):
            pass
        elif action_code == "INTERNAL_HOST_CONTAINMENT":
            firewall_status = "INTERNAL HOST ALERT"
            if not any(log.get("target") == src_ip and log.get("action") == "HOST_CONTAINMENT" for log in audit_logs[:5]):
                audit_logs.insert(0, {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "action": "HOST_CONTAINMENT",
                    "target": src_ip,
                    "actor": "Policy Engine",
                    "reason": f"Internal host flagged for {res['predicted_threat']} activity in protected subnet.",
                    "result": "ALERTED"
                })
        elif action_code == "WHITELIST_PROTECTED":
            firewall_status = "WHITELIST PROTECTED"
        elif risk_lvl in ["High", "Critical"]:
            if src_ip in dismissed_ips:
                firewall_status = "ANALYST PERMITTED"
            elif mitigation_mode == "Autonomous Auto-Block":
                rule_spec = res.get("firewall_rule_specs", {})
                if backend_is_real:
                    exec_res = execute_firewall_rule(src_ip, simulate_safe=False)
                    if exec_res.get("success"):
                        block_status = "BLOCKED (Real OS Netsh)"
                        res_outcome = "SUCCESS"
                    else:
                        block_status = "BLOCKED (Sandbox Fallback - Admin Required)"
                        res_outcome = "FAILURE (Fallback to Sandbox)"
                    mode_desc = "Windows Defender Netsh"
                else:
                    exec_res = execute_firewall_rule(src_ip, simulate_safe=True)
                    block_status = "BLOCKED (Simulated Sandbox)"
                    res_outcome = "SUCCESS"
                    mode_desc = "Simulated Sandbox"

                blocklist[src_ip] = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "quarantined_at": time.time(),
                    "ttl_seconds": 3600,
                    "threat": res["predicted_threat"],
                    "risk_score": res["risk_score"],
                    "risk_level": risk_lvl,
                    "status": block_status,
                    "mode": mode_desc,
                    "rule": rule_spec.get("netsh_command", "")
                }
                firewall_status = "QUARANTINED"

                if not any(log.get("target") == src_ip and log.get("action") == "IP_QUARANTINED" for log in audit_logs[:5]):
                    audit_logs.insert(0, {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "action": "IP_QUARANTINED",
                        "target": src_ip,
                        "actor": f"Autonomous Mitigation ({mode_desc})",
                        "reason": f"{risk_lvl} severity threat {res['predicted_threat']} detected (Score: {res['risk_score']}). Status: {res_outcome}",
                        "result": "SUCCESS" if "SUCCESS" in res_outcome else "FAILURE"
                    })
            else: # Human-in-the-Loop Approval Queue
                if src_ip not in blocklist or not blocklist[src_ip]["status"].startswith("BLOCKED"):
                    is_already_pending = (src_ip in blocklist and blocklist[src_ip]["status"] == "PENDING_APPROVAL")
                    blocklist[src_ip] = {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "quarantined_at": time.time(),
                        "ttl_seconds": 3600,
                        "threat": res["predicted_threat"],
                        "risk_score": res["risk_score"],
                        "risk_level": risk_lvl,
                        "status": "PENDING_APPROVAL",
                        "mode": enforcement_backend,
                        "rule": res.get("firewall_rule_specs", {}).get("netsh_command", "")
                    }
                    firewall_status = "PENDING APPROVAL"
                    if not is_already_pending:
                        audit_logs.insert(0, {
                            "timestamp": time.strftime("%H:%M:%S"),
                            "action": "FLAGGED_PENDING_APPROVAL",
                            "target": src_ip,
                            "actor": "Human-in-the-Loop Gateway",
                            "reason": f"{risk_lvl} threat {res['predicted_threat']} flagged; awaiting security analyst authorization.",
                            "result": "PENDING"
                        })
                else:
                    firewall_status = "DROPPED (Firewall Active)"
        elif risk_lvl == "Medium":
            firewall_status = "RATE-LIMITED"
        else:
            firewall_status = "ACCEPTED"

        flow_record = {
            **flow,
            **res,
            "firewall_status": firewall_status,
            "stream_source": source_type,
            "timestamp": time.strftime("%H:%M:%S")
        }
        alerts_history.insert(0, flow_record)
        state["total_flows_processed"] += 1

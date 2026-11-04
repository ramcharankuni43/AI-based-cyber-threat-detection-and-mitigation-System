import time
import pandas as pd
from services.mitigation_service import execute_firewall_rule, remove_firewall_rule, generate_firewall_rule

def purge_expired_quarantines(blocklist: dict, audit_logs: list, enforcement_backend: str = "Simulated Mitigation") -> list[str]:
    """
    Evaluates 1-hour TTL leases for quarantined IPs and safely releases expired entries.
    Returns list of released IPs.
    100% Simulated Safe Demo Mode: Operates purely in software state.
    """
    now = time.time()
    expired_ips = []
    
    for ip, meta in list(blocklist.items()):
        if meta.get("status", "").startswith("BLOCKED"):
            quarantined_at = meta.get("quarantined_at", now)
            ttl = meta.get("ttl_seconds", 3600)
            if (now - quarantined_at) >= ttl:
                expired_ips.append(ip)

    for ip in expired_ips:
        remove_firewall_rule(ip, simulate_safe=True)
        del blocklist[ip]
        audit_logs.insert(0, {
            "timestamp": time.strftime("%H:%M:%S"),
            "action": "QUARANTINE_EXPIRED",
            "target": ip,
            "actor": "TTL Decay Daemon (Simulated Mitigation)",
            "reason": "1-Hour quarantine lease expired. IP released from simulated blocklist.",
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
    1. Evaluates incoming flow vectors against active simulated firewall blocklist.
    2. Runs multi-class AI inference and anomaly scoring.
    3. Manages incident lifecycle (New -> Investigating -> Mitigated / Dismissed).
    4. Executes simulated mitigation (quarantine) or queues for analyst review.
    5. Records compliance audit trail without touching host OS.
    """
    blocklist = state.setdefault("blocklist", {})
    audit_logs = state.setdefault("audit_logs", [])
    alerts_history = state.setdefault("alerts_history", [])
    incidents = state.setdefault("incidents", [])
    dismissed_ips = state.setdefault("dismissed_ips", set())
    mitigation_mode = state.get("mitigation_mode", "Autonomous Auto-Block")

    for _, row in batch_df.iterrows():
        flow = row.to_dict()
        src_ip = str(flow.get("src_ip", "")).strip()

        is_already_blocked = (src_ip in blocklist and blocklist[src_ip]["status"].startswith("BLOCKED"))

        if is_already_blocked:
            state["blocked_traffic_drops"] += 1
            firewall_status = "DROPPED (Simulated Quarantine Active)"
        else:
            firewall_status = "PENDING_EVALUATION"

        res = inference_module.analyze_event(flow, model_override="random_forest")
        action_code = res.get("action_code", "LOG_ONLY")
        risk_lvl = res.get("risk_level", "Low")
        predicted_threat = res.get("predicted_threat", "Normal")

        # Simulated Mitigation Decision Flow
        if firewall_status.startswith("DROPPED"):
            pass
        elif action_code == "INTERNAL_HOST_CONTAINMENT":
            firewall_status = "INTERNAL HOST ALERT"
            if not any(log.get("target") == src_ip and log.get("action") == "HOST_CONTAINMENT" for log in audit_logs[:5]):
                audit_logs.insert(0, {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "action": "HOST_CONTAINMENT",
                    "target": src_ip,
                    "actor": "Policy Engine (Simulated)",
                    "reason": f"Internal host flagged for {predicted_threat} in protected subnet.",
                    "result": "ALERTED"
                })
        elif action_code == "WHITELIST_PROTECTED":
            firewall_status = "WHITELIST PROTECTED"
        elif risk_lvl in ["High", "Critical"] or (predicted_threat != "Normal" and res.get("confidence", 0) >= 0.70):
            if src_ip in dismissed_ips:
                firewall_status = "ANALYST DISMISSED"
            elif mitigation_mode == "Autonomous Auto-Block":
                rule_spec = res.get("firewall_rule_specs", {})
                exec_res = execute_firewall_rule(src_ip, simulate_safe=True)
                if exec_res.get("success", False):
                    block_status = "BLOCKED (Simulated Mitigation)"
                    mode_desc = "Simulated Mitigation (Safe Demo Mode)"

                    blocklist[src_ip] = {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "quarantined_at": time.time(),
                        "ttl_seconds": 3600,
                        "threat": predicted_threat,
                        "risk_score": res["risk_score"],
                        "risk_level": risk_lvl,
                        "status": block_status,
                        "mode": mode_desc,
                        "rule": rule_spec.get("netsh_command", "")
                    }
                    firewall_status = "SIMULATED QUARANTINED"

                    if not any(log.get("target") == src_ip and log.get("action") == "IP_QUARANTINED" for log in audit_logs[:5]):
                        audit_logs.insert(0, {
                            "timestamp": time.strftime("%H:%M:%S"),
                            "action": "SIMULATED_IP_QUARANTINED",
                            "target": src_ip,
                            "actor": "Autonomous Policy (Simulated)",
                            "reason": f"{risk_lvl} threat {predicted_threat} detected (Score: {res['risk_score']}). Added to simulated blocklist.",
                            "result": "SUCCESS"
                        })
                else:
                    firewall_status = f"QUARANTINE REJECTED ({exec_res.get('error', 'Safety rule')})"
                    audit_logs.insert(0, {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "action": "AUTO_MITIGATION_REJECTED",
                        "target": src_ip,
                        "actor": "Autonomous Policy (Simulated)",
                        "reason": f"Auto-mitigation blocked by safety engine: {exec_res.get('error', 'Safety rule')}",
                        "result": "REJECTED"
                    })
            else: # Human-in-the-Loop Approval Queue
                if src_ip not in blocklist or not blocklist[src_ip]["status"].startswith("BLOCKED"):
                    is_already_pending = (src_ip in blocklist and blocklist[src_ip]["status"] == "PENDING_APPROVAL")
                    blocklist[src_ip] = {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "quarantined_at": time.time(),
                        "ttl_seconds": 3600,
                        "threat": predicted_threat,
                        "risk_score": res["risk_score"],
                        "risk_level": risk_lvl,
                        "status": "PENDING_APPROVAL",
                        "mode": "Simulated Mitigation (Safe Demo Mode)",
                        "rule": res.get("firewall_rule_specs", {}).get("netsh_command", "")
                    }
                    firewall_status = "PENDING APPROVAL"
                    if not is_already_pending:
                        audit_logs.insert(0, {
                            "timestamp": time.strftime("%H:%M:%S"),
                            "action": "FLAGGED_PENDING_APPROVAL",
                            "target": src_ip,
                            "actor": "Human-in-the-Loop Gateway",
                            "reason": f"{risk_lvl} threat {predicted_threat} awaiting analyst authorization.",
                            "result": "PENDING"
                        })
                else:
                    firewall_status = "DROPPED (Simulated Quarantine Active)"
        elif risk_lvl == "Medium":
            firewall_status = "SIMULATED RATE-LIMITED"
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

        # Incident Lifecycle Tracking (New -> Investigating -> Mitigated / Dismissed)
        # Create an incident for any abnormal or attack traffic
        if predicted_threat != "Normal" or risk_lvl in ["High", "Critical"]:
            # Ensure monotonic unique ID: max(existing_ids) + 1
            existing_ids = []
            for inc in incidents:
                inc_id_str = str(inc.get("incident_id", ""))
                if inc_id_str.startswith("INC-"):
                    try:
                        existing_ids.append(int(inc_id_str.split("-")[1]))
                    except (ValueError, IndexError):
                        pass
            next_id = (max(existing_ids) + 1) if existing_ids else 1
            inc_id = f"INC-{next_id:04d}"
            lifecycle_status = "Mitigated" if "QUARANTINED" in firewall_status else ("Dismissed" if "DISMISSED" in firewall_status else "New")
            incident_entry = {
                "incident_id": inc_id,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": str(flow.get("dst_ip", "10.0.0.5")),
                "proto": str(flow.get("proto", "tcp")),
                "service": str(flow.get("service", "-")),
                "predicted_threat": predicted_threat,
                "confidence": res.get("confidence", 0.0),
                "risk_score": res.get("risk_score", 0.0),
                "severity": risk_lvl,
                "anomaly_score": res.get("anomaly_score", 0.0),
                "status": lifecycle_status,
                "mitigation_status": firewall_status,
                "flow_telemetry": {
                    "spkts": flow.get("spkts", 0),
                    "dpkts": flow.get("dpkts", 0),
                    "sbytes": flow.get("sbytes", 0),
                    "dbytes": flow.get("dbytes", 0),
                    "dur": flow.get("dur", 0.0),
                    "rate": flow.get("rate", 0.0),
                    "failed_login_count": flow.get("failed_login_count", 0),
                    "connection_count": flow.get("connection_count", 1)
                },
                "shap_explanation": res.get("shap_explanation", {}),
                "mitre_attack": res.get("mitre_attack", {}),
                "notes": f"Incident generated from {source_type} ({batch_label})"
            }
            incidents.insert(0, incident_entry)

def update_incident_status(state: dict, incident_id: str, new_status: str, actor: str = "SOC Security Analyst", analyst_notes: str = "") -> dict:
    """
    Manages incident lifecycle transitions:
    Allowed states: "New", "Investigating", "Mitigated", "Dismissed"
    Synchronizes simulated mitigation state and logs compliance audit record.
    """
    valid_statuses = ["New", "Investigating", "Mitigated", "Dismissed"]
    if new_status not in valid_statuses:
        return {"success": False, "message": f"Invalid status '{new_status}'. Must be one of {valid_statuses}."}

    incidents = state.get("incidents", [])
    target_inc = next((inc for inc in incidents if inc.get("incident_id") == incident_id), None)
    if not target_inc:
        return {"success": False, "message": f"Incident {incident_id} not found."}

    old_status = target_inc.get("status", "New")
    target_inc["status"] = new_status
    if analyst_notes:
        target_inc["analyst_notes"] = analyst_notes
    target_inc["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")

    src_ip = target_inc.get("src_ip")
    blocklist = state.setdefault("blocklist", {})
    audit_logs = state.setdefault("audit_logs", [])
    dismissed_ips = state.setdefault("dismissed_ips", set())

    action_type = f"INCIDENT_{new_status.upper()}"
    reason = f"Analyst transitioned incident {incident_id} lifecycle status from '{old_status}' to '{new_status}'."
    if analyst_notes:
        reason += f" Notes: {analyst_notes}"

    # Synchronize simulated mitigation state
    if new_status == "Mitigated":
        rule_spec = generate_firewall_rule(src_ip)
        exec_res = execute_firewall_rule(src_ip, simulate_safe=True)
        if not exec_res.get("success", False):
            err_msg = exec_res.get("error", "Mitigation rejected by safety engine.")
            audit_logs.insert(0, {
                "timestamp": time.strftime("%H:%M:%S"),
                "action": "INCIDENT_MITIGATION_REJECTED",
                "target": f"{incident_id} ({src_ip})",
                "actor": actor,
                "reason": f"Failed to mitigate incident {incident_id}: {err_msg}",
                "result": "REJECTED"
            })
            return {"success": False, "error": err_msg, "message": f"Mitigation rejected for {src_ip}: {err_msg}"}
        blocklist[src_ip] = {
            "timestamp": time.strftime("%H:%M:%S"),
            "quarantined_at": time.time(),
            "ttl_seconds": 3600,
            "threat": target_inc.get("predicted_threat", "Unknown"),
            "risk_score": target_inc.get("risk_score", 80.0),
            "risk_level": target_inc.get("severity", "High"),
            "status": "BLOCKED (Simulated Mitigation)",
            "mode": "Simulated Mitigation (Safe Demo Mode)",
            "rule": rule_spec.get("netsh_command", "")
        }
        target_inc["mitigation_status"] = "SIMULATED QUARANTINED"
    elif new_status == "Dismissed":
        if src_ip in blocklist:
            del blocklist[src_ip]
        dismissed_ips.add(src_ip)
        remove_firewall_rule(src_ip, simulate_safe=True)
        target_inc["mitigation_status"] = "ANALYST DISMISSED"

    audit_logs.insert(0, {
        "timestamp": time.strftime("%H:%M:%S"),
        "action": action_type,
        "target": f"{incident_id} ({src_ip})",
        "actor": actor,
        "reason": reason,
        "result": "SUCCESS"
    })

    return {"success": True, "incident": target_inc, "message": f"Incident {incident_id} marked as {new_status}."}


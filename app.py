import os
import sys

# Auto-launcher: if user executes `python app.py` directly from terminal instead of `streamlit run app.py`
if __name__ == "__main__":
    try:
        from streamlit.runtime import exists as _st_exists
        if not _st_exists():
            import subprocess
            print("\n[*] Starting Streamlit SOC Dashboard on http://localhost:8501 ...")
            print("[*] (Running command: streamlit run app.py)\n")
            cmd = [sys.executable, "-m", "streamlit", "run", os.path.abspath(__file__)] + sys.argv[1:]
            subprocess.run(cmd)
            sys.exit(0)
    except Exception:
        pass

import time
import json
import datetime
import warnings

# Suppress benign sklearn parallel configuration warning
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", message=".*sklearn.utils.parallel.delayed.*")

import pandas as pd
import numpy as np
import streamlit as st

# Project directories
BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
STATE_FILE = os.path.join(DATA_DIR, "soc_state.json")

import inference
from model_trainer import train_and_evaluate_all
from storage import StateStore
from services import (
    authenticate_user,
    has_permission,
    is_demo_quick_login_enabled,
    execute_firewall_rule,
    remove_firewall_rule,
    generate_firewall_rule,
    is_safe_to_block_ip,
    TRUSTED_WHITELIST_IPS,
    process_stream_batch as alert_process_stream_batch,
    purge_expired_quarantines,
    update_incident_status
)

# Page configuration
st.set_page_config(
    page_title="CyberSentinel • AI SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Professional Cybersecurity SaaS Design System
st.markdown("""
<style>
    /* Global Background & Font */
    .stApp {
        background-color: #080c14;
        color: #e2e8f0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    /* Sidebar Dark Theme Styling */
    section[data-testid="stSidebar"] {
        background-color: #0b1120 !important;
        border-right: 1px solid #1e293b;
    }
    section[data-testid="stSidebar"] div[data-testid="stMarkdownContainer"] p,
    section[data-testid="stSidebar"] div[data-testid="stMarkdownContainer"] h5,
    section[data-testid="stSidebar"] div[data-testid="stMarkdownContainer"] strong,
    section[data-testid="stSidebar"] label,
    section[data-testid="stSidebar"] span {
        color: #e2e8f0 !important;
    }
    section[data-testid="stSidebar"] div[role="radiogroup"] label {
        color: #94a3b8 !important;
        font-size: 0.88rem !important;
        padding: 6px 8px;
        border-radius: 6px;
        transition: all 0.15s ease;
    }
    section[data-testid="stSidebar"] div[role="radiogroup"] label:hover {
        background-color: #1e293b;
        color: #38bdf8 !important;
    }
    
    /* Header Bar */
    .soc-brand-bar {
        background: linear-gradient(90deg, #0d1527 0%, #111c33 100%);
        border: 1px solid #1e293b;
        border-left: 4px solid #06b6d4;
        border-radius: 8px;
        padding: 14px 20px;
        margin-bottom: 16px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .soc-brand-title {
        font-size: 1.25rem;
        font-weight: 600;
        color: #f8fafc;
        margin: 0;
        letter-spacing: -0.01em;
    }
    .soc-brand-subtitle {
        font-size: 0.8rem;
        color: #94a3b8;
        margin: 2px 0 0 0;
    }
    
    /* Streamlit Top Header Bar */
    header[data-testid="stHeader"] {
        background-color: #080c14 !important;
    }
    header[data-testid="stHeader"] button {
        color: #94a3b8 !important;
    }

    /* Metric Cards */
    div[data-testid="stMetric"] {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 10px 14px;
    }
    div[data-testid="stMetricLabel"] {
        white-space: normal !important;
        overflow: visible !important;
    }
    div[data-testid="stMetricLabel"] * {
        white-space: normal !important;
        overflow: visible !important;
        text-overflow: unset !important;
    }
    div[data-testid="stMetric"] label {
        color: #94a3b8 !important;
        font-size: 0.72rem !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        white-space: normal !important;
        overflow: visible !important;
        text-overflow: unset !important;
        word-break: break-word !important;
        line-height: 1.2 !important;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #38bdf8 !important;
        font-family: 'JetBrains Mono', 'SF Mono', Consolas, monospace;
        font-size: 1.45rem !important;
        font-weight: 700 !important;
    }
    
    /* Status Badges */
    .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }
    .badge-critical { background-color: #450a0a; color: #f87171; border: 1px solid #7f1d1d; }
    .badge-high     { background-color: #431407; color: #fb923c; border: 1px solid #9a3412; }
    .badge-medium   { background-color: #422006; color: #facc15; border: 1px solid #854d0e; }
    .badge-low      { background-color: #022c22; color: #34d399; border: 1px solid #065f46; }
    .badge-info     { background-color: #082f49; color: #38bdf8; border: 1px solid #0369a1; }

    /* Clean Card Containers */
    .soc-card {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
    }
    .soc-card-header {
        font-size: 0.9rem;
        font-weight: 600;
        color: #f1f5f9;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    
    /* Mode Banners */
    .banner-sandbox {
        background-color: #082f49;
        border: 1px solid #0284c7;
        color: #bae6fd;
        padding: 8px 14px;
        border-radius: 6px;
        font-size: 0.8rem;
        margin-bottom: 14px;
    }
    .banner-host {
        background-color: #450a0a;
        border: 1px solid #dc2626;
        color: #fecaca;
        padding: 8px 14px;
        border-radius: 6px;
        font-size: 0.8rem;
        margin-bottom: 14px;
    }
</style>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# PERSISTENT ATOMIC STATE MANAGEMENT (Finding B)
# -------------------------------------------------------------
state_store = StateStore(STATE_FILE)
persisted = state_store.load_state()

def save_persisted_state():
    """Atomically persists state to disk with automatic .bak fail-safe backup."""
    return state_store.save_state({
        "blocklist": st.session_state.blocklist,
        "incidents": st.session_state.incidents[:200],
        "audit_logs": st.session_state.audit_logs[:200],
        "total_flows_processed": st.session_state.total_flows_processed,
        "blocked_traffic_drops": st.session_state.blocked_traffic_drops,
        "dismissed_ips": list(st.session_state.get("dismissed_ips", []))
    })

def check_and_purge_expired_quarantines():
    """Purges expired quarantined IP addresses based on 1-hour TTL lease in software memory."""
    expired = purge_expired_quarantines(
        st.session_state.blocklist,
        st.session_state.audit_logs,
        "Simulated Mitigation (Safe Demo Mode)"
    )
    if expired:
        save_persisted_state()
    return expired

# Initialize Session State
if "alerts_history" not in st.session_state:
    st.session_state.alerts_history = []
if "incidents" not in st.session_state:
    st.session_state.incidents = persisted.get("incidents", [])
if "blocklist" not in st.session_state:
    st.session_state.blocklist = persisted.get("blocklist", {})
if "audit_logs" not in st.session_state:
    st.session_state.audit_logs = persisted.get("audit_logs", [])
if "total_flows_processed" not in st.session_state:
    st.session_state.total_flows_processed = persisted.get("total_flows_processed", 0)
if "blocked_traffic_drops" not in st.session_state:
    st.session_state.blocked_traffic_drops = persisted.get("blocked_traffic_drops", 0)
if "dismissed_ips" not in st.session_state:
    st.session_state.dismissed_ips = set(persisted.get("dismissed_ips", []))
if "mitigation_mode" not in st.session_state:
    st.session_state.mitigation_mode = "Autonomous Auto-Block"
if "enforcement_backend" not in st.session_state:
    st.session_state.enforcement_backend = "Simulated Mitigation (Safe Demo Mode)"
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

# Periodic TTL purge check
check_and_purge_expired_quarantines()

# -------------------------------------------------------------
# AUTHENTICATION & ACCESS CONTROL GATE (Finding D)
# -------------------------------------------------------------
if st.session_state.authenticated_user is None:
    st.markdown("""
    <div style="max-width: 520px; margin: 40px auto 16px auto; text-align: center;">
        <div style="font-size: 2.5rem; margin-bottom: 6px;">🛡️</div>
        <h2 style="color: #f8fafc; margin-bottom: 4px; font-weight: 700;">CyberSentinel SOC Platform</h2>
        <p style="color: #94a3b8; font-size: 0.88rem;">AI Intrusion Detection & Automated Mitigation System</p>
    </div>
    """, unsafe_allow_html=True)

    auth_col1, auth_col2, auth_col3 = st.columns([1, 2, 1])
    with auth_col2:
        with st.form("soc_login_form"):
            st.markdown("##### 🔐 SOC Analyst & Administrator Sign In")
            login_user = st.text_input("Username:", placeholder="admin or analyst")
            login_pass = st.text_input("Password:", type="password", placeholder="admin123 or analyst123")
            submitted = st.form_submit_button("Sign In to Console", width="stretch")
            if submitted:
                authed = authenticate_user(login_user, login_pass)
                if authed:
                    st.session_state.authenticated_user = authed
                    st.success(f"Welcome, {authed['display_name']}!")
                    st.rerun()
                else:
                    st.error("Invalid credentials. Please verify username and password.")

        if is_demo_quick_login_enabled():
            st.markdown("<p style='text-align: center; color: #64748b; font-size: 0.8rem; margin: 12px 0;'>— OR QUICK EVALUATION ACCESS (LOCAL DEMO) —</p>", unsafe_allow_html=True)
            demo_col1, demo_col2 = st.columns(2)
            with demo_col1:
                if st.button("🔑 Login as Admin", width="stretch", help="Full permissions: retraining, state management"):
                    from services.auth_service import ADMIN_USER, ADMIN_PASS
                    st.session_state.authenticated_user = authenticate_user(ADMIN_USER, ADMIN_PASS)
                    st.rerun()
            with demo_col2:
                if st.button("👤 Login as Analyst", width="stretch", help="Triage permissions: threat investigation, quarantine approval"):
                    from services.auth_service import ANALYST_USER, ANALYST_PASS
                    st.session_state.authenticated_user = authenticate_user(ANALYST_USER, ANALYST_PASS)
                    st.rerun()

    st.stop()

cur_user = st.session_state.get("authenticated_user") or {}
cur_role = cur_user.get("role", "analyst")

# Periodic TTL purge check
check_and_purge_expired_quarantines()

# -------------------------------------------------------------
# SIDEBAR: CLEAN RESTRAINED NAVIGATION & SYSTEM STATUS
# -------------------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div style="padding: 4px 0 12px 0; border-bottom: 1px solid #1e293b; margin-bottom: 12px;">
        <div style="font-size: 1.15rem; font-weight: 700; color: #f8fafc; letter-spacing: -0.02em;">
            🛡️ CyberSentinel
        </div>
        <div style="font-size: 0.75rem; color: #06b6d4; font-weight: 500; margin-top: 2px;">
            AI SOC Detection & Mitigation
        </div>
    </div>
    """, unsafe_allow_html=True)

    role_color = "#f43f5e" if cur_role == "admin" else "#38bdf8"
    role_bg = "#450a0a" if cur_role == "admin" else "#082f49"
    st.markdown(f"""
    <div style="background-color: #0f172a; border: 1px solid #1e293b; padding: 10px 12px; border-radius: 6px; margin-bottom: 10px;">
        <div style="font-size: 0.82rem; font-weight: 600; color: #f8fafc;">{cur_user.get('display_name', 'Operator')}</div>
        <div style="margin-top: 4px;">
            <span style="background-color: {role_bg}; color: {role_color}; padding: 2px 6px; border-radius: 4px; font-size: 0.68rem; font-weight: 700; text-transform: uppercase; font-family: monospace;">
                ROLE: {cur_role.upper()}
            </span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("🚪 Sign Out", width="stretch"):
        st.session_state.authenticated_user = None
        st.rerun()

    st.markdown("##### Navigation")
    nav_page = st.radio(
        "SOC Operations",
        options=[
            "Dashboard",
            "AI Detection",
            "Incident Investigation",
            "Simulated Mitigation",
            "Reports & Audit History"
        ],
        format_func=lambda x: {
            "Dashboard": "📊  Dashboard",
            "AI Detection": "🤖  AI Detection",
            "Incident Investigation": "🔍  Incident Investigation",
            "Simulated Mitigation": "🛡️  Simulated Mitigation",
            "Reports & Audit History": "📑  Reports & Audit History"
        }.get(x, x),
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("""
    <div style="background-color: #0f172a; border: 1px solid #1e293b; padding: 12px; border-radius: 6px; font-size: 0.78rem; color: #94a3b8; line-height: 1.6;">
        <strong style="color: #f8fafc;">System Posture:</strong><br>
        • <strong>Engine:</strong> Random Forest Classifier<br>
        • <strong>Anomaly:</strong> Isolation Forest<br>
        • <strong>Mitigation:</strong> Simulated Mitigation<br>
        • <strong>Protected:</strong> <code>10.0.0.0/24</code><br>
        • <strong>TTL Lease:</strong> 60 Mins
    </div>
    """, unsafe_allow_html=True)

# -------------------------------------------------------------
# BRAND HEADER & OPERATIONAL MODE BANNER
# -------------------------------------------------------------
st.markdown(f"""
<div class="soc-brand-bar">
    <div>
        <h1 class="soc-brand-title">AI SOC Intrusion Detection & Automated Mitigation System</h1>
        <p class="soc-brand-subtitle">Real-Time Machine Learning • Explainable AI (SHAP) • MITRE ATT&CK • Simulated Quarantine</p>
    </div>
    <div>
        <span class="badge badge-info">{st.session_state.mitigation_mode}</span>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="banner-sandbox">
    🟢 <strong>Operational Mode: Simulated Mitigation (Safe College Demo)</strong> — Malicious IPs are quarantined in software memory. Host OS security rules and network interfaces are never modified.
</div>
""", unsafe_allow_html=True)

active_quarantined_ips = [ip for ip, b in st.session_state.blocklist.items() if b.get("status", "").startswith("BLOCKED")]

# -------------------------------------------------------------
# TELEMETRY STREAM INGESTION ENGINE
# -------------------------------------------------------------
def process_stream_batch(batch_df: pd.DataFrame, batch_label: str, source_type: str = "Simulation Replay"):
    """Unified telemetry stream ingestor with consistent mitigation and quarantine rules."""
    check_and_purge_expired_quarantines()
    state_dict = {
        "blocklist": st.session_state.blocklist,
        "incidents": st.session_state.incidents,
        "audit_logs": st.session_state.audit_logs,
        "alerts_history": st.session_state.alerts_history,
        "dismissed_ips": st.session_state.dismissed_ips,
        "mitigation_mode": st.session_state.mitigation_mode,
        "enforcement_backend": "Simulated Mitigation (Safe Demo Mode)",
        "blocked_traffic_drops": st.session_state.blocked_traffic_drops,
        "total_flows_processed": st.session_state.total_flows_processed
    }
    alert_process_stream_batch(batch_df, batch_label, source_type, state_dict, inference)
    st.session_state.blocked_traffic_drops = state_dict["blocked_traffic_drops"]
    st.session_state.total_flows_processed = state_dict["total_flows_processed"]
    save_persisted_state()

# =============================================================
# 1. DASHBOARD
# =============================================================
if nav_page == "Dashboard":
    st.caption("SOC Console > Operations Dashboard")

    total_records = st.session_state.total_flows_processed
    detected_threats = sum(1 for a in st.session_state.alerts_history if a.get("predicted_threat", "Normal") != "Normal")
    normal_traffic = sum(1 for a in st.session_state.alerts_history if a.get("predicted_threat", "Normal") == "Normal")
    high_risk = sum(1 for a in st.session_state.alerts_history if a.get("risk_level") in ["High", "Critical"])
    quarantined = len(active_quarantined_ips)

    # 5 Essential KPI Metric Cards
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.metric("Total Traffic Records", f"{total_records:,}", help="Total network telemetry flow packets processed by the AI system.")
    with c2:
        st.metric("Detected Threats", f"{detected_threats:,}", help="Flows classified as malicious cyber threats (DoS, Port Scan, Brute Force).")
    with c3:
        st.metric("Normal Traffic", f"{normal_traffic:,}", help="Benign operational baseline network traffic flows.")
    with c4:
        st.metric("High-Risk Incidents", f"{high_risk:,}", help="Incidents evaluated with Risk Score >= 60.0 (High or Critical severity).")
    with c5:
        st.metric("Quarantined Incidents", f"{quarantined:,}", help="Unique malicious host IP addresses currently quarantined in simulated blocklist.")

    st.markdown("---")
    d1, d2 = st.columns([1, 1])
    with d1:
        st.markdown("#### Threat Activity & Incident Breakdown")
        if st.session_state.alerts_history:
            threat_counts = {}
            for a in st.session_state.alerts_history:
                t = a.get("predicted_threat", "Normal")
                threat_counts[t] = threat_counts.get(t, 0) + 1
            df_threats = pd.DataFrame(list(threat_counts.items()), columns=["Threat Type", "Count"]).set_index("Threat Type")
            st.bar_chart(df_threats, color="#38bdf8")
        else:
            st.info("No network events processed yet. Go to **AI Detection** to replay traffic scenarios or upload a batch CSV dataset.")

    with d2:
        st.markdown("#### Active Mitigation Status & Health")
        if active_quarantined_ips:
            st.warning(f"⚠️ **{len(active_quarantined_ips)} host(s) actively quarantined** in simulated blocklist.")
            quick_list = []
            for ip in active_quarantined_ips[:5]:
                b_info = st.session_state.blocklist.get(ip, {})
                quick_list.append({
                    "Quarantined IP": ip,
                    "Threat": b_info.get("threat", "Unknown"),
                    "Risk Score": b_info.get("risk_score", 0),
                    "Status": b_info.get("status", "BLOCKED")
                })
            st.dataframe(pd.DataFrame(quick_list), width="stretch")
        else:
            st.success("✅ **Perimeter Clear:** No host IP addresses are currently quarantined.")

        st.markdown("""
        <div style="background-color: #0f172a; border: 1px solid #1e293b; padding: 12px; border-radius: 6px; font-size: 0.8rem; color: #94a3b8; margin-top: 10px;">
            • <strong>Detection Engine:</strong> Online (Supervised Random Forest Classifier)<br>
            • <strong>Anomaly Detector:</strong> Online (Unsupervised Isolation Forest)<br>
            • <strong>Mitigation Mode:</strong> Simulated Mitigation (Safe Demonstration)<br>
            • <strong>Protected Subnet:</strong> <code>10.0.0.0/24</code> (Immutable Allowlist)<br>
            • <strong>Quarantine Auto-Decay:</strong> 60-Minute Sliding TTL Window
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### Recent Security Alerts")
    if st.session_state.alerts_history:
        recent_records = []
        for a in st.session_state.alerts_history[:8]:
            recent_records.append({
                "Timestamp": a.get("timestamp", "-"),
                "Source IP": a.get("src_ip", "-"),
                "Dest IP": a.get("dst_ip", "-"),
                "Threat Type": a.get("predicted_threat", "Normal"),
                "Severity": a.get("risk_level", "Low"),
                "Risk Score": a.get("risk_score", 0.0),
                "Confidence": f"{a.get('confidence', 0):.1%}",
                "Mitigation Status": a.get("firewall_status", "ACCEPTED")
            })
        st.dataframe(pd.DataFrame(recent_records), width="stretch")
    else:
        st.caption("Recent security alerts will appear here in real time as network telemetry is ingested.")

# =============================================================
# 2. AI DETECTION
# =============================================================
elif nav_page == "AI Detection":
    st.caption("SOC Console > AI Threat Detection & Model Evaluation")
    st.subheader("AI-Based Network Threat Detection")
    st.caption("Simulate network traffic scenarios, upload and validate CSV flow datasets, and inspect comparative ML model performance.")

    ai_tab1, ai_tab2, ai_tab3 = st.tabs([
        "Traffic Simulation & Scenario Replay",
        "Dataset Upload & Schema Validator",
        "ML Model Comparison Benchmarks"
    ])

    with ai_tab1:
        st.markdown("#### Safe Attack Scenario Replay")
        st.caption("Inject pre-recorded multi-class traffic scenarios into the AI decision pipeline:")

        sc1, sc2, sc3, sc4 = st.columns(4)
        with sc1:
            if st.button("🟢 Stream Normal Traffic", key="btn_sim_normal", width="stretch"):
                f = os.path.join(DATA_DIR, "normal.csv")
                if os.path.exists(f):
                    df_n = pd.read_csv(f).sample(n=10, random_state=int(time.time()) % 1000)
                    process_stream_batch(df_n, "Normal Baseline", "Simulation Replay (Normal)")
                    st.success("Replayed 10 normal baseline flows!")
                    st.rerun()
                else:
                    st.error("normal.csv not found.")
        with sc2:
            if st.button("🔴 Trigger DDoS Attack", key="btn_sim_ddos", width="stretch"):
                f = os.path.join(DATA_DIR, "ddos.csv")
                if os.path.exists(f):
                    df_d = pd.read_csv(f).sample(n=10, random_state=int(time.time()) % 1000)
                    process_stream_batch(df_d, "DoS/DDoS Attack", "Simulation Replay (DDoS)")
                    st.warning("DDoS volumetric attack replayed and analyzed!")
                    st.rerun()
                else:
                    st.error("ddos.csv not found.")
        with sc3:
            if st.button("🟠 Trigger Port Scan", key="btn_sim_scan", width="stretch"):
                f = os.path.join(DATA_DIR, "portscan.csv")
                if os.path.exists(f):
                    df_p = pd.read_csv(f).sample(n=10, random_state=int(time.time()) % 1000)
                    process_stream_batch(df_p, "Port Scan", "Simulation Replay (Port Scan)")
                    st.warning("Port Scan reconnaissance sweep replayed and analyzed!")
                    st.rerun()
                else:
                    st.error("portscan.csv not found.")
        with sc4:
            if st.button("🟣 Trigger Brute Force", key="btn_sim_brute", width="stretch"):
                f = os.path.join(DATA_DIR, "bruteforce.csv")
                if os.path.exists(f):
                    df_b = pd.read_csv(f).sample(n=10, random_state=int(time.time()) % 1000)
                    process_stream_batch(df_b, "Brute Force", "Simulation Replay (Brute Force)")
                    st.warning("Brute Force credential attack replayed and analyzed!")
                    st.rerun()
                else:
                    st.error("bruteforce.csv not found.")

        if active_quarantined_ips:
            drop_test_ip = active_quarantined_ips[0]
            st.markdown("---")
            st.info(f"💡 **Mitigation Verification:** IP `{drop_test_ip}` is currently quarantined in the simulated blocklist. Replay packets from this IP to verify subsequent traffic is actively dropped:")
            if st.button(f"🛡️ Replay Traffic from Quarantined IP ({drop_test_ip})", key="btn_verify_drop", width="stretch"):
                for _ in range(5):
                    sample_flow = {
                        "src_ip": drop_test_ip,
                        "dst_ip": "10.0.0.5",
                        "proto": "tcp",
                        "service": "http",
                        "state": "REQ",
                        "dur": 0.001,
                        "spkts": 400,
                        "sbytes": 350000,
                        "rate": 7000,
                        "connection_count": 900
                    }
                    st.session_state.blocked_traffic_drops += 1
                    sample_flow["firewall_status"] = "DROPPED (Simulated Quarantine Active)"
                    sample_flow["stream_source"] = "Verification Replay (Quarantined IP)"
                    res = inference.analyze_event(sample_flow, model_override="random_forest")
                    st.session_state.alerts_history.insert(0, {**sample_flow, **res, "timestamp": time.strftime("%H:%M:%S")})
                    st.session_state.total_flows_processed += 1
                save_persisted_state()
                st.success(f"5 packets from {drop_test_ip} were dropped by active simulated quarantine!")
                st.rerun()

    with ai_tab2:
        st.markdown("#### Offline Network Flow CSV Classification & Schema Validation")
        st.caption("Upload network flow CSV datasets to validate features, detect unseen categories, and classify flows offline:")
        uploaded_file = st.file_uploader("Upload Network Flow CSV File:", type=["csv"])
        if uploaded_file is not None:
            try:
                df_raw = pd.read_csv(uploaded_file)
                val_res = inference.validate_and_prepare_csv(df_raw)

                # Schema Validation Summary Card
                v_col1, v_col2, v_col3, v_col4 = st.columns(4)
                with v_col1:
                    st.metric("Total Records", f"{val_res['total_rows']:,}")
                with v_col2:
                    st.metric("Features Present", f"{len(val_res['present_numerical'])} / 24 Num")
                with v_col3:
                    st.metric("Categoricals", f"{len(val_res['present_categorical'])} / 3 Cat")
                with v_col4:
                    st.metric("Coerced Values", f"{val_res['coerced_nan_count']} NaNs")

                if val_res["unseen_categories"]:
                    st.warning(f"⚠️ **Unseen Categories Detected:** {val_res['unseen_categories']}. These are safely mapped to reserved code 0 rather than misclassified.")
                else:
                    st.success("✅ **Schema Verified:** Input matches model feature definitions.")

                if st.button("🚀 Run Batch AI Inference", width="stretch", key="btn_run_csv_batch"):
                    with st.spinner("Classifying network flows..."):
                        batch_res = inference.predict_batch_csv(df_raw, model_name="random_forest")
                        st.success(f"Processed {batch_res['total_flows']} flows in {batch_res['total_time_seconds']}s (Avg latency: {batch_res['avg_latency_ms']} ms/flow)!")

                        # Summary metrics
                        b1, b2, b3 = st.columns(3)
                        with b1:
                            st.metric("Model Architecture", "Random Forest")
                        with b2:
                            st.metric("Threat Breakdown", str(batch_res["class_breakdown"]))
                        with b3:
                            st.metric("High-Risk Flows", batch_res["high_risk_count"])

                        df_out = pd.DataFrame(batch_res["results"])
                        st.dataframe(df_out, width="stretch")

                        csv_export = df_out.to_csv(index=False).encode('utf-8')
                        st.download_button("📥 Download Inference Results (CSV)", data=csv_export, file_name="ai_detection_results.csv", mime="text/csv", width="stretch")
            except Exception as e:
                st.error(f"Error validating or processing CSV: {str(e)}")

    with ai_tab3:
        st.markdown("#### Scientific ML Model Comparison Benchmark")
        st.caption("Evaluated on stratified 15% independent hold-out test set with zero data leakage:")

        report = inference.get_model_comparison_report()
        models = report.get("models", {})

        comp_rows = []
        for key, m in models.items():
            roc_val = m.get("roc_auc")
            roc_str = f"{float(roc_val):.4f}" if roc_val is not None else "N/A"
            comp_rows.append({
                "Model Architecture": m.get("name"),
                "Type": m.get("type"),
                "Accuracy": f"{m.get('accuracy', 0):.4f}",
                "F1-Score": f"{m.get('f1_score_weighted', m.get('f1_score', 0)):.4f}",
                "Precision": f"{m.get('precision_weighted', m.get('precision', 0)):.4f}",
                "Recall": f"{m.get('recall_weighted', m.get('recall', 0)):.4f}",
                "FPR": f"{m.get('false_positive_rate', 0):.4f}",
                "ROC-AUC": roc_str,
                "Latency/Flow": f"{m.get('prediction_latency_ms', 0):.3f} ms",
                "Target Met?": "YES" if m.get("meets_f1_target", True) else "NO"
            })
        st.table(pd.DataFrame(comp_rows))

        # Stratified Validation Split Performance
        val_metrics = report.get("validation_metrics", {})
        if val_metrics:
            st.markdown("##### Stratified Validation Split Performance (Zero-Leakage Tuning Check)")
            val_rows = []
            for mkey, vdata in val_metrics.items():
                val_rows.append({
                    "Model Architecture": mkey.replace("_", " ").title(),
                    "Validation Metric": "Accuracy & F1" if "accuracy" in vdata else "Anomaly F1",
                    "Score / Reading": f"Accuracy: {vdata.get('accuracy', '-')}, F1: {vdata.get('f1_score', vdata.get('anomaly_f1', '-'))}"
                })
            st.dataframe(pd.DataFrame(val_rows), width="stretch")

        # Dataset Provenance Notice
        ds_info = report.get("dataset", {})
        if ds_info.get("benchmark_note"):
            st.info(f"ℹ️ **Dataset Provenance & Benchmark Note:** {ds_info.get('benchmark_note')}")

        # Per-Class Metrics Matrix
        st.markdown("##### Per-Class Performance Breakdown Matrix (Random Forest)")
        rf_per_class = models.get("random_forest", {}).get("per_class_metrics", {})
        if rf_per_class:
            pc_rows = []
            for cname, pcm in rf_per_class.items():
                pc_rows.append({
                    "Threat Category": cname,
                    "Support": pcm.get("support"),
                    "Precision": f"{pcm.get('precision', 0):.4f}",
                    "Recall": f"{pcm.get('recall', 0):.4f}",
                    "F1-Score": f"{pcm.get('f1_score', 0):.4f}",
                    "FPR": f"{pcm.get('false_positive_rate', 0):.4f}",
                    "FNR": f"{pcm.get('false_negative_rate', 0):.4f}"
                })
            st.dataframe(pd.DataFrame(pc_rows), width="stretch")

        # Side-by-side Confusion Matrices
        col_cm1, col_cm2 = st.columns(2)
        classes = report.get("dataset", {}).get("classes", [])
        with col_cm1:
            st.markdown("##### Random Forest Confusion Matrix")
            rf_cm = models.get("random_forest", {}).get("confusion_matrix", [])
            if rf_cm and classes:
                st.dataframe(pd.DataFrame(rf_cm, index=classes, columns=classes), width="stretch")
        with col_cm2:
            st.markdown("##### XGBoost Confusion Matrix")
            xgb_cm = models.get("xgboost", {}).get("confusion_matrix", [])
            if xgb_cm and classes:
                st.dataframe(pd.DataFrame(xgb_cm, index=classes, columns=classes), width="stretch")

        st.markdown("##### Top Global Informative Features (Gini Importance)")
        imp_features = report.get("feature_importance", [])
        if imp_features:
            df_imp = pd.DataFrame(imp_features).set_index("feature")
            st.bar_chart(df_imp, color="#38bdf8")

        # Admin Retrain Button
        if has_permission(cur_role, "retrain_models"):
            st.markdown("---")
            if st.button("🔄 Retrain ML Models (Admin Action)", help="Retrains Random Forest, XGBoost, and Isolation Forest models"):
                with st.spinner("Retraining models and evaluating independent test set..."):
                    train_and_evaluate_all()
                    inference.reload_all_artifacts()
                    st.success("Retrained and reloaded model artifacts successfully!")
                    st.rerun()

# =============================================================
# 3. INCIDENT INVESTIGATION
# =============================================================
elif nav_page == "Incident Investigation":
    st.caption("SOC Console > Incident Investigation & Root Cause")
    st.subheader("Security Incident Investigation")
    st.caption("Detailed incident triage, flow telemetry, explainable AI (SHAP), MITRE ATT&CK alignment, and lifecycle state management.")

    incidents_list = st.session_state.incidents
    if not incidents_list:
        st.info("No security incidents recorded yet. Generate threat traffic via **AI Detection** to create incidents.")
    else:
        # Filters
        f1, f2 = st.columns([1, 2])
        with f1:
            status_filter = st.selectbox("Filter by Lifecycle Status:", options=["All Statuses", "New", "Investigating", "Mitigated", "Dismissed"])
        with f2:
            search_query = st.text_input("Search Incidents by ID or IP:", placeholder="e.g. INC-0001 or 198.51")

        filtered_incidents = incidents_list.copy()
        if status_filter != "All Statuses":
            filtered_incidents = [inc for inc in filtered_incidents if inc.get("status") == status_filter]
        if search_query:
            filtered_incidents = [
                inc for inc in filtered_incidents
                if search_query.lower() in inc.get("incident_id", "").lower() or search_query.lower() in inc.get("src_ip", "").lower()
            ]

        if not filtered_incidents:
            st.info("No incidents match the active filter criteria.")
        else:
            inc_options = [
                f"{inc.get('incident_id')}: {inc.get('predicted_threat')} from {inc.get('src_ip')} ({inc.get('severity')} Severity, Status: {inc.get('status')})"
                for inc in filtered_incidents[:50]
            ]
            selected_option = st.selectbox("Select Incident to Investigate:", options=inc_options)
            sel_inc_id = selected_option.split(":")[0].strip()
            target_inc = next((inc for inc in incidents_list if inc.get("incident_id") == sel_inc_id), filtered_incidents[0])

            # Primary Incident Header Cards
            st.markdown("#### Primary Incident Overview")
            p1, p2, p3, p4 = st.columns(4)
            with p1:
                st.metric("Incident ID", target_inc.get("incident_id"))
            with p2:
                st.metric("Attack Category", target_inc.get("predicted_threat", "Unknown"))
            with p3:
                st.metric("Severity Tier", target_inc.get("severity", "High"))
            with p4:
                st.metric("Calibrated Risk Score", f"{target_inc.get('risk_score', 0):.1f} / 100")

            i_col1, i_col2 = st.columns(2)
            with i_col1:
                st.markdown(f"""
                - **Source IP Address:** `{target_inc.get('src_ip')}`
                - **Destination IP Address:** `{target_inc.get('dst_ip')}`
                - **Detection Timestamp:** `{target_inc.get('timestamp')}`
                - **Protocol / Service:** `{target_inc.get('proto', 'tcp').upper()} / {target_inc.get('service', '-')}`
                """)
            with i_col2:
                st.markdown(f"""
                - **Model Confidence:** `{target_inc.get('confidence', 0):.2%}`
                - **Isolation Forest Anomaly Score:** `{target_inc.get('anomaly_score', 0):.4f}`
                - **Lifecycle Status:** `{target_inc.get('status', 'New')}`
                - **Mitigation Status:** `{target_inc.get('mitigation_status', 'None')}`
                """)

            # Lifecycle Transition Controls
            st.markdown("---")
            st.markdown("#### Incident Lifecycle Management (`New` → `Investigating` → `Mitigated` / `Dismissed`)")
            analyst_notes = st.text_input("Analyst Notes / Rationale:", value=target_inc.get("analyst_notes", ""), placeholder="e.g. Verified anomalous SYN flood behavior")

            act1, act2, act3 = st.columns(3)
            with act1:
                if st.button("🔍 Mark as Investigating", key=f"btn_inv_{target_inc.get('incident_id')}", width="stretch"):
                    res = update_incident_status(st.session_state, target_inc["incident_id"], "Investigating", actor=cur_user.get("display_name", "Analyst"), analyst_notes=analyst_notes)
                    save_persisted_state()
                    st.success(res["message"])
                    st.rerun()
            with act2:
                if st.button("🛡️ Simulate Quarantine (Mitigate)", key=f"btn_mit_{target_inc.get('incident_id')}", width="stretch"):
                    res = update_incident_status(st.session_state, target_inc["incident_id"], "Mitigated", actor=cur_user.get("display_name", "Analyst"), analyst_notes=analyst_notes)
                    save_persisted_state()
                    st.success(f"Quarantined IP {target_inc.get('src_ip')} in simulated blocklist and marked incident as Mitigated.")
                    st.rerun()
            with act3:
                if st.button("❌ Dismiss Incident", key=f"btn_dis_{target_inc.get('incident_id')}", width="stretch"):
                    res = update_incident_status(st.session_state, target_inc["incident_id"], "Dismissed", actor=cur_user.get("display_name", "Analyst"), analyst_notes=analyst_notes)
                    save_persisted_state()
                    st.info(f"Incident {target_inc.get('incident_id')} dismissed and IP released from blocklist.")
                    st.rerun()

            st.markdown("---")
            # Expandable Details
            with st.expander("📋 Flow Telemetry Attributes", expanded=False):
                fl = target_inc.get("flow_telemetry", {})
                t1, t2 = st.columns(2)
                with t1:
                    st.markdown(f"**Packets (Sent / Recv):** `{fl.get('spkts', 0)}` / `{fl.get('dpkts', 0)}`")
                    st.markdown(f"**Bytes Sent / Recv:** `{fl.get('sbytes', 0):,}` / `{fl.get('dbytes', 0):,}`")
                    st.markdown(f"**Flow Duration:** `{fl.get('dur', 0):.4f}s`")
                with t2:
                    st.markdown(f"**Flow Rate:** `{fl.get('rate', 0):,.1f} pkts/s`")
                    st.markdown(f"**Failed Logins:** `{fl.get('failed_login_count', 0)}`")
                    st.markdown(f"**Connection Count:** `{fl.get('connection_count', 1)}`")

            with st.expander("📊 Explainable AI: SHAP Feature Attribution Inspector", expanded=True):
                shap_data = target_inc.get("shap_explanation", {})
                top_feats = shap_data.get("top_features", [])
                st.caption(f"Feature contribution values calculated relative to attack class **{target_inc.get('predicted_threat')}** using TreeExplainer:")
                if top_feats:
                    feat_df = pd.DataFrame(top_feats)
                    st.dataframe(feat_df[["feature", "shap_value", "feature_value", "impact_direction"]], width="stretch")
                    chart_df = feat_df.set_index("feature")["shap_value"]
                    st.bar_chart(chart_df, color="#06b6d4")
                    st.caption("Positive SHAP values push classification toward the threat category; negative values push toward alternative classes.")
                else:
                    st.info("Feature values conform to expected operational baseline profile.")

            with st.expander("🎯 MITRE ATT&CK Framework Mapping", expanded=False):
                mitre = target_inc.get("mitre_attack", {})
                if mitre and mitre.get("technique_id") != "None":
                    st.markdown(f"**Technique:** [{mitre.get('technique_id')} - {mitre.get('technique_name')}]({mitre.get('url')})")
                    st.caption(f"Tactic: **{mitre.get('tactic')}** • Sub-Technique: **{mitre.get('sub_technique')}**")
                    st.info(mitre.get("description", ""))
                else:
                    st.caption("Standard operational traffic (Not classified as an attack technique).")

            with st.expander("📐 Risk Scoring Formulation & Mathematical Weights", expanded=False):
                st.markdown("""
                - **Internal Composite Risk Scale:** 0.0 to 100.0 (Standardized CVSS v3.1 Impact Alignment)
                - **Formula:** `Composite Risk (0-100) = (Base Impact * 40) + (Model Confidence * 30) + (Anomaly Score * 15) + (Telemetry Modifier * 15)`
                - **Weight Distribution:**
                  - Base Severity Impact: 40% (DoS: 0.85, Brute Force: 0.75, Port Scan: 0.55, Normal: 0.05)
                  - Classifier Posterior Probability: 30%
                  - Isolation Forest Anomaly Score: 15%
                  - Flow Telemetry Volume Modifier: 15%
                - **Threshold Severity Tiers:**
                  - Low: 0.0 – 29.9 (Informational / Baseline Activity)
                  - Medium: 30.0 – 59.9 (Suspicious Anomaly / Monitored)
                  - High: 60.0 – 79.9 (Confirmed Attack Signature / Quarantined)
                  - Critical: 80.0 – 100.0 (Severe Breach / Emergency Containment)
                """)

# =============================================================
# 4. SIMULATED MITIGATION
# =============================================================
elif nav_page == "Simulated Mitigation":
    st.caption("SOC Console > Simulated Mitigation Management")
    st.subheader("Simulated Mitigation Management")
    st.caption("Active simulated quarantine blocklist, sliding TTL auto-decay, manual release controls, and firewall rule syntax viewer.")

    st.markdown("""
    <div class="banner-sandbox">
        🟢 <strong>SIMULATED MITIGATION (Safe Demo Mode):</strong> In this college demonstration mode, malicious IP addresses are quarantined in software memory and subsequent traffic from blocked IPs is dropped in memory. Host operating system firewall rules are never modified.
    </div>
    """, unsafe_allow_html=True)

    col_fw1, col_fw2 = st.columns([2, 1])

    with col_fw1:
        st.markdown("#### 🚫 Active Quarantined IP Blocklist")
        active_blocked = {ip: b for ip, b in st.session_state.blocklist.items() if b.get("status", "").startswith("BLOCKED")}

        hdr1, hdr2 = st.columns([3, 1])
        with hdr2:
            if st.button("⏱️ Purge Expired TTL", help="Evaluates 60-minute TTL leases and releases expired quarantined IPs", width="stretch"):
                expired = check_and_purge_expired_quarantines()
                if expired:
                    st.success(f"Released {len(expired)} expired IP(s): {', '.join(expired)}")
                else:
                    st.info("No quarantine entries currently expired.")
                st.rerun()

        if not active_blocked:
            st.info("No host IP addresses are currently quarantined in the simulated blocklist.")
        else:
            block_data = []
            now_ts = time.time()
            for ip, b in active_blocked.items():
                elapsed_mins = int((now_ts - b.get("quarantined_at", now_ts)) / 60)
                rem_mins = max(0, 60 - elapsed_mins)
                block_data.append({
                    "IP Address": ip,
                    "Threat": b.get("threat"),
                    "Risk Score": b.get("risk_score"),
                    "Severity": b.get("risk_level", "High"),
                    "Enforcement Status": b.get("status"),
                    "Quarantined At": b.get("timestamp"),
                    "Remaining TTL": f"{rem_mins} mins remaining"
                })
            st.dataframe(pd.DataFrame(block_data), width="stretch")

            # Selection and Manual Release
            unblock_ip = st.selectbox("Select IP to Release:", options=list(active_blocked.keys()))
            rule_spec = inference.generate_firewall_rule(unblock_ip)

            u_col1, u_col2 = st.columns([1, 1])
            with u_col1:
                if st.button(f"🔓 Release IP {unblock_ip}", width="stretch", key="btn_manual_release"):
                    remove_firewall_rule(unblock_ip, simulate_safe=True)
                    del st.session_state.blocklist[unblock_ip]
                    st.session_state.audit_logs.insert(0, {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "action": "MANUAL_UNBLOCK",
                        "target": unblock_ip,
                        "actor": f"SOC Security Analyst ({cur_user.get('display_name', 'Analyst')})",
                        "reason": "Security analyst manually released IP from simulated quarantine blocklist.",
                        "result": "SUCCESS"
                    })
                    save_persisted_state()
                    st.success(f"IP {unblock_ip} released from simulated quarantine blocklist.")
                    st.rerun()

            with u_col2:
                with st.expander("Inspect Netsh & PowerShell Rule Syntax", expanded=False):
                    st.code(rule_spec.get("netsh_command", ""), language="bash")
                    st.caption("PowerShell: `" + rule_spec.get("powershell_command", "") + "`")
                    st.caption("Rollback: `" + rule_spec.get("rollback_command", "") + "`")
                    st.info("ℹ️ Demonstrates the exact syntax an enterprise firewall integration would deploy without modifying the host OS.")

    with col_fw2:
        st.markdown("#### 🛡️ Protected Infrastructure Allowlist")
        st.caption("Critical infrastructure IPs and CIDR subnets immune from automatic quarantine:")
        whitelist_rows = [
            {"Asset / Subnet": ip, "Role / Rationale": role}
            for ip, role in inference.TRUSTED_WHITELIST_IPS.items()
        ]
        whitelist_rows.extend([
            {"Asset / Subnet": "10.0.0.0/24", "Role / Rationale": "Core Protected Server Subnet (CIDR)"},
            {"Asset / Subnet": "127.0.0.0/8", "Role / Rationale": "Localhost Internal Loopback (CIDR)"},
            {"Asset / Subnet": "192.168.1.0/24", "Role / Rationale": "Management Workstation LAN"}
        ])
        st.dataframe(pd.DataFrame(whitelist_rows), width="stretch")
        st.caption("Fail-safe safeguard: Rule generator automatically rejects any block command targeted at protected assets.")

# =============================================================
# 5. REPORTS & AUDIT HISTORY
# =============================================================
elif nav_page == "Reports & Audit History":
    st.caption("SOC Console > Reports, Incident History & Compliance Audit")
    st.subheader("SOC Reports & Audit History")
    st.caption("Historical incident tracking, detection logs, simulated mitigation history, and compliance audit exports.")

    rep_tab1, rep_tab2, rep_tab3 = st.tabs([
        "Incident History",
        "Detection History",
        "Mitigation & Audit Logs"
    ])

    with rep_tab1:
        st.markdown("#### Complete Incident History")
        if st.session_state.incidents:
            inc_data = []
            for inc in st.session_state.incidents:
                inc_data.append({
                    "Incident ID": inc.get("incident_id"),
                    "Timestamp": inc.get("timestamp"),
                    "Source IP": inc.get("src_ip"),
                    "Dest IP": inc.get("dst_ip"),
                    "Attack Category": inc.get("predicted_threat"),
                    "Risk Score": inc.get("risk_score"),
                    "Severity": inc.get("severity"),
                    "Lifecycle Status": inc.get("status"),
                    "Mitigation Status": inc.get("mitigation_status")
                })
            df_inc = pd.DataFrame(inc_data)
            st.dataframe(df_inc, width="stretch")
            csv_inc = df_inc.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Download Incident History (CSV)", data=csv_inc, file_name="incident_history.csv", mime="text/csv", width="stretch")
        else:
            st.info("No security incidents recorded yet.")

    with rep_tab2:
        st.markdown("#### Historical Detection Feed")
        if st.session_state.alerts_history:
            # Filters
            f_col1, f_col2 = st.columns(2)
            with f_col1:
                t_filt = st.selectbox("Filter by Threat:", options=["All Threats", "Normal", "DoS/DDoS", "Port Scan", "Brute Force"])
            with f_col2:
                s_filt = st.selectbox("Filter by Severity:", options=["All Severities", "Critical", "High", "Medium", "Low"])

            feed = st.session_state.alerts_history.copy()
            if t_filt != "All Threats":
                feed = [a for a in feed if a.get("predicted_threat") == t_filt]
            if s_filt != "All Severities":
                feed = [a for a in feed if a.get("risk_level") == s_filt]

            det_rows = []
            for a in feed:
                det_rows.append({
                    "Timestamp": a.get("timestamp", "-"),
                    "Source IP": a.get("src_ip", "-"),
                    "Dest IP": a.get("dst_ip", "-"),
                    "Threat": a.get("predicted_threat", "Normal"),
                    "Severity": a.get("risk_level", "Low"),
                    "Risk Score": a.get("risk_score", 0.0),
                    "Confidence": f"{a.get('confidence', 0):.2%}",
                    "Mitigation Status": a.get("firewall_status", "ACCEPTED")
                })
            df_det = pd.DataFrame(det_rows)
            st.dataframe(df_det, width="stretch")
            csv_det = df_det.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Download Detection History (CSV)", data=csv_det, file_name="detection_history.csv", mime="text/csv", width="stretch")
        else:
            st.info("No detection history recorded yet.")

    with rep_tab3:
        st.markdown("#### Compliance Audit Trail")
        search_log = st.text_input("Search Logs by IP, Action, or Actor:", placeholder="e.g. 198.51, QUARANTINE, or Analyst")
        f_logs = st.session_state.audit_logs.copy()
        if search_log:
            f_logs = [
                log for log in f_logs
                if search_log.lower() in str(log.get("target", "")).lower()
                or search_log.lower() in str(log.get("action", "")).lower()
                or search_log.lower() in str(log.get("actor", "")).lower()
                or search_log.lower() in str(log.get("reason", "")).lower()
            ]

        if f_logs:
            df_audit = pd.DataFrame(f_logs)
            st.dataframe(df_audit, width="stretch")
            csv_audit = df_audit.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Download Audit Trail (CSV)", data=csv_audit, file_name="soc_compliance_audit_log.csv", mime="text/csv", width="stretch")
        else:
            st.info("No audit entries match the search criteria.")

        # Admin Clear State Option
        st.markdown("---")
        st.markdown("##### Administrative Demo State Management")
        if st.button("🧹 Reset Demo State (Admin Action)", help="Clears event logs, incidents, blocklist, and session state for a fresh demonstration"):
            if not has_permission(cur_role, "clear_demo_state"):
                st.error("Admin role required: You must be signed in as Administrator to clear state.")
            else:
                st.session_state.alerts_history = []
                st.session_state.incidents = []
                st.session_state.blocklist = {}
                st.session_state.audit_logs = []
                st.session_state.total_flows_processed = 0
                st.session_state.blocked_traffic_drops = 0
                st.session_state.dismissed_ips = set()
                state_store.clear_state()
                st.success("Clean demo state restored successfully!")
                st.rerun()

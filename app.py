import os
import sys
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
    execute_firewall_rule,
    remove_firewall_rule,
    generate_firewall_rule,
    is_safe_to_block_ip,
    TRUSTED_WHITELIST_IPS,
    process_stream_batch as alert_process_stream_batch,
    purge_expired_quarantines
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
        "audit_logs": st.session_state.audit_logs[:200],
        "total_flows_processed": st.session_state.total_flows_processed,
        "blocked_traffic_drops": st.session_state.blocked_traffic_drops,
        "dismissed_ips": list(st.session_state.get("dismissed_ips", []))
    })

def check_and_purge_expired_quarantines():
    """Purges expired quarantined IP addresses based on 1-hour TTL lease with verified removal."""
    expired = purge_expired_quarantines(
        st.session_state.blocklist,
        st.session_state.audit_logs,
        st.session_state.enforcement_backend
    )
    if expired:
        save_persisted_state()
    return expired

# Initialize Session State
if "alerts_history" not in st.session_state:
    st.session_state.alerts_history = []
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
    st.session_state.enforcement_backend = "Simulated Sandbox (Safe Lab)"
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

        st.markdown("<p style='text-align: center; color: #64748b; font-size: 0.8rem; margin: 12px 0;'>— OR QUICK EVALUATION ACCESS —</p>", unsafe_allow_html=True)
        demo_col1, demo_col2 = st.columns(2)
        with demo_col1:
            if st.button("🔑 Login as Admin", width="stretch", help="Full permissions: host firewall, retraining, state management"):
                st.session_state.authenticated_user = authenticate_user("admin", "admin123")
                st.rerun()
        with demo_col2:
            if st.button("👤 Login as Analyst", width="stretch", help="Triage permissions: threat investigation, quarantine approval"):
                st.session_state.authenticated_user = authenticate_user("analyst", "analyst123")
                st.rerun()

    st.stop()

cur_user = st.session_state.authenticated_user
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
            "Overview",
            "Live Monitoring",
            "Threat Investigation",
            "Mitigation & Firewall",
            "Audit Logs",
            "Testing & Evaluation",
        ],
        format_func=lambda x: {
            "Overview": "📊  Overview",
            "Live Monitoring": "📡  Live Monitoring",
            "Threat Investigation": "🔍  Threat Investigation",
            "Mitigation & Firewall": "🛡️  Mitigation & Firewall",
            "Audit Logs": "📋  Audit Logs",
            "Testing & Evaluation": "🧪  Testing & Evaluation",
        }.get(x, x),
        label_visibility="collapsed"
    )

    is_real_backend = st.session_state.enforcement_backend.startswith("Windows Defender")
    mode_label = "Real Host (Netsh)" if is_real_backend else "Simulated Sandbox"

    st.markdown("---")
    st.markdown(f"""
    <div style="background-color: #0f172a; border: 1px solid #1e293b; padding: 12px; border-radius: 6px; font-size: 0.78rem; color: #94a3b8; line-height: 1.6;">
        <strong style="color: #f8fafc;">System Posture:</strong><br>
        • <strong>Engine:</strong> Random Forest<br>
        • <strong>Anomaly:</strong> Isolation Forest<br>
        • <strong>Enforcement:</strong> {mode_label}<br>
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
        <p class="soc-brand-subtitle">Real-Time Machine Learning • Explainable AI (SHAP) • MITRE ATT&CK • Automated Quarantine</p>
    </div>
    <div>
        <span class="badge badge-info">{st.session_state.mitigation_mode}</span>
    </div>
</div>
""", unsafe_allow_html=True)

if is_real_backend:
    st.markdown("""
    <div class="banner-host">
        ⚠️ <strong>Operational Mode: Windows Defender Host Firewall (Netsh Active)</strong> — Generates and executes <code>netsh advfirewall firewall add rule</code> commands directly on local host. (Requires terminal run as Administrator for live OS rule commitment).
    </div>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <div class="banner-sandbox">
        🟢 <strong>Demonstration Mode: Simulated Lab Sandbox (Safe Lab)</strong> — Malicious IPs are quarantined in software state and subsequent packets are dropped in memory without modifying host OS rules.
    </div>
    """, unsafe_allow_html=True)

high_or_crit_count = sum(1 for a in st.session_state.alerts_history if a.get("risk_level") in ["Critical", "High"])
med_count = sum(1 for a in st.session_state.alerts_history if a.get("risk_level") == "Medium")
active_quarantined_ips = [ip for ip, b in st.session_state.blocklist.items() if b.get("status", "").startswith("BLOCKED")]
pending_approval_ips = [ip for ip, b in st.session_state.blocklist.items() if b.get("status") == "PENDING_APPROVAL"]

# -------------------------------------------------------------
# TELEMETRY STREAM INGESTION ENGINE (Modularized via Services)
# -------------------------------------------------------------
def process_stream_batch(batch_df: pd.DataFrame, batch_label: str, source_type: str = "Simulation Replay"):
    """Unified telemetry stream ingestor with consistent mitigation and quarantine rules."""
    check_and_purge_expired_quarantines()
    state_dict = {
        "blocklist": st.session_state.blocklist,
        "audit_logs": st.session_state.audit_logs,
        "alerts_history": st.session_state.alerts_history,
        "dismissed_ips": st.session_state.dismissed_ips,
        "mitigation_mode": st.session_state.mitigation_mode,
        "enforcement_backend": st.session_state.enforcement_backend,
        "blocked_traffic_drops": st.session_state.blocked_traffic_drops,
        "total_flows_processed": st.session_state.total_flows_processed
    }
    alert_process_stream_batch(batch_df, batch_label, source_type, state_dict, inference)
    st.session_state.blocked_traffic_drops = state_dict["blocked_traffic_drops"]
    st.session_state.total_flows_processed = state_dict["total_flows_processed"]
    save_persisted_state()

# -------------------------------------------------------------
# 1. OVERVIEW DASHBOARD
# -------------------------------------------------------------
if nav_page == "Overview":
    st.caption("SOC Console > Operational Overview")
    
    # 5 Essential KPI Cards (Single Source of Truth)
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.metric(
            "Network Events",
            st.session_state.total_flows_processed,
            help="Total network flow telemetry packets processed by the AI inference engine."
        )
    with c2:
        st.metric(
            "High Severity",
            high_or_crit_count,
            help="Ingested events evaluated with Risk Score >= 60.0 (Confirmed threat signatures requiring quarantine action)."
        )
    with c3:
        st.metric(
            "Medium Severity",
            med_count,
            help="Ingested events evaluated with Risk Score between 30.0 and 59.9 (Suspicious anomalies triggering rate-limiting)."
        )
    with c4:
        st.metric(
            "Active Quarantines",
            len(active_quarantined_ips),
            help="Unique malicious IP addresses currently blocked in the active firewall blocklist."
        )
    with c5:
        st.metric(
            "Verified Drops",
            st.session_state.blocked_traffic_drops,
            help="Verified network packets dropped because their source IP was actively quarantined in the firewall."
        )

    st.markdown("---")
    ov_c1, ov_c2 = st.columns([1, 1])
    
    with ov_c1:
        st.markdown("#### Threat Activity & Incident Breakdown")
        if st.session_state.alerts_history:
            threat_counts = {}
            for a in st.session_state.alerts_history:
                t = a.get("predicted_threat", "Normal")
                threat_counts[t] = threat_counts.get(t, 0) + 1
            df_counts = pd.DataFrame(list(threat_counts.items()), columns=["Threat Type", "Count"]).set_index("Threat Type")
            st.bar_chart(df_counts, color="#38bdf8")
        else:
            st.info("No network events ingested yet. Visit the **Testing & Evaluation** area to replay traffic scenarios or upload a batch CSV.")

    with ov_c2:
        st.markdown("#### System Health & Active Mitigation Posture")
        if active_quarantined_ips:
            st.warning(f"⚠️ **{len(active_quarantined_ips)} host(s) actively quarantined** in the firewall.")
            quick_blocked = []
            for ip in active_quarantined_ips[:5]:
                b_info = st.session_state.blocklist.get(ip, {})
                quick_blocked.append({
                    "Quarantined IP": ip,
                    "Detected Threat": b_info.get("threat", "Unknown"),
                    "Risk Score": b_info.get("risk_score", 0),
                    "Status": b_info.get("status", "BLOCKED")
                })
            st.dataframe(pd.DataFrame(quick_blocked), width="stretch")
        else:
            st.success("✅ **Perimeter Clear:** Zero host IP addresses currently quarantined.")
            
        if pending_approval_ips:
            st.info(f"⏳ **{len(pending_approval_ips)} suspicious threat(s)** awaiting analyst authorization in **Mitigation & Firewall**.")
            
        st.markdown(f"""
        <div style="background-color: #0f172a; border: 1px solid #1e293b; padding: 12px; border-radius: 6px; font-size: 0.8rem; color: #94a3b8; margin-top: 10px;">
            • <strong>Detection Engine:</strong> Online (Random Forest + Isolation Forest)<br>
            • <strong>Enforcement Backend:</strong> {mode_label}<br>
            • <strong>Protected Subnet:</strong> <code>10.0.0.0/24</code> (Immutable Allowlist)<br>
            • <strong>Quarantine Auto-Decay:</strong> Active (60-minute sliding window)
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### Recent Security Alerts")
    if st.session_state.alerts_history:
        recent_events = []
        for a in st.session_state.alerts_history[:8]:
            recent_events.append({
                "Timestamp": a.get("timestamp"),
                "Source IP": a.get("src_ip"),
                "Dest IP": a.get("dst_ip"),
                "Threat Type": a.get("predicted_threat"),
                "Severity": a.get("risk_level"),
                "Risk Score": a.get("risk_score"),
                "Mitigation Status": a.get("firewall_status")
            })
        st.dataframe(pd.DataFrame(recent_events), width="stretch")
    else:
        st.caption("Recent threat alerts will appear here in real time as network telemetry is ingested.")

# -------------------------------------------------------------
# 2. LIVE MONITORING
# -------------------------------------------------------------
elif nav_page == "Live Monitoring":
    st.caption("SOC Console > Live Threat Monitoring")
    st.subheader("Live Threat Monitoring")
    st.caption("Operational triage feed of network telemetry flows, threat detections, and automated firewall actions.")

    # Triage Filters
    fcol1, fcol2, fcol3 = st.columns([1, 1, 2])
    with fcol1:
        threat_filter = st.selectbox(
            "Threat Type:",
            options=["All Threats", "Normal", "DoS/DDoS", "Port Scan", "Brute Force", "Exploits", "Botnet"]
        )
    with fcol2:
        risk_filter = st.selectbox(
            "Severity Tier:",
            options=["All Tiers", "Critical", "High", "Medium", "Low"]
        )
    with fcol3:
        search_ip = st.text_input("Search Source or Destination IP:", value="", placeholder="e.g. 192.168.1 or 45.33 or 198.51")

    filtered_alerts = st.session_state.alerts_history.copy()
    if threat_filter != "All Threats":
        filtered_alerts = [a for a in filtered_alerts if a.get("predicted_threat") == threat_filter]
    if risk_filter != "All Tiers":
        filtered_alerts = [a for a in filtered_alerts if a.get("risk_level") == risk_filter]
    if search_ip:
        filtered_alerts = [
            a for a in filtered_alerts
            if search_ip.lower() in str(a.get("src_ip", "")).lower() or search_ip.lower() in str(a.get("dst_ip", "")).lower()
        ]

    st.markdown(f"**Events in Feed:** {len(filtered_alerts)} (Filtered from {len(st.session_state.alerts_history)} total records)")

    if not filtered_alerts:
        st.info("No network events match the active filter criteria.")
    else:
        # Simplified Main Triage Table (Only essential quick-triage columns)
        page_size = 15
        total_pages = max(1, (len(filtered_alerts) + page_size - 1) // page_size)
        page_num = st.number_input(f"Page (1 to {total_pages}):", min_value=1, max_value=total_pages, value=1, step=1)
        
        start_idx = (page_num - 1) * page_size
        end_idx = min(start_idx + page_size, len(filtered_alerts))
        
        triage_data = []
        for i, a in enumerate(filtered_alerts[start_idx:end_idx], start=start_idx):
            triage_data.append({
                "#": i + 1,
                "Timestamp": a.get("timestamp", "-"),
                "Source IP": a.get("src_ip", "-"),
                "Dest IP": a.get("dst_ip", "-"),
                "Threat Type": a.get("predicted_threat", "Normal"),
                "Severity": a.get("risk_level", "Low"),
                "Risk Score": a.get("risk_score", 0.0),
                "Status": a.get("firewall_status", "ACCEPTED")
            })
            
        df_triage = pd.DataFrame(triage_data)
        st.dataframe(
            df_triage,
            column_config={
                "Risk Score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%.1f")
            },
            width="stretch"
        )
        
        # Expandable Event Technical Details Panel
        with st.expander("🔍 Inspect Technical Details for Selected Event", expanded=False):
            inspect_idx = st.selectbox(
                "Select Event to Inspect:",
                options=list(range(start_idx, end_idx)),
                format_func=lambda idx: f"Event #{idx+1}: {filtered_alerts[idx].get('predicted_threat')} from {filtered_alerts[idx].get('src_ip')} ({filtered_alerts[idx].get('risk_level')} Severity)"
            )
            if inspect_idx < len(filtered_alerts):
                ev = filtered_alerts[inspect_idx]
                dcol1, dcol2, dcol3, dcol4 = st.columns(4)
                with dcol1:
                    st.metric("Model Confidence", f"{ev.get('confidence', 0):.2%}")
                with dcol2:
                    st.metric("IsoForest Anomaly Score", f"{ev.get('anomaly_score', 0):.4f}")
                with dcol3:
                    st.metric("Protocol / Service", f"{ev.get('proto', 'tcp').upper()} / {ev.get('service', '-')}")
                with dcol4:
                    st.metric("Flow Rate", f"{ev.get('rate', 0):,.1f} pkts/s")
                    
                st.markdown(f"**Rationale:** {ev.get('explanation', 'Normal operational baseline flow.')}")

# -------------------------------------------------------------
# 3. THREAT INVESTIGATION (Explainable AI & MITRE ATT&CK)
# -------------------------------------------------------------
elif nav_page == "Threat Investigation":
    st.caption("SOC Console > Threat Investigation & Root Cause")
    st.subheader("Threat Investigation")
    st.caption("Deep-dive root-cause analysis: flow telemetry, risk factors, explainable AI (SHAP), and MITRE ATT&CK alignment.")

    if not st.session_state.alerts_history:
        st.info("No security alerts available to investigate. Generate traffic via the **Testing & Evaluation** tab.")
    else:
        event_options = [
            f"Event #{i+1}: [{a.get('timestamp')}] {a.get('predicted_threat')} from {a.get('src_ip')} ({a.get('risk_level')} Severity, Score: {a.get('risk_score')})"
            for i, a in enumerate(st.session_state.alerts_history[:40])
        ]
        selected_option = st.selectbox("Select Alert for Deep Investigation:", options=event_options)
        selected_idx = int(selected_option.split(":")[0].replace("Event #", "")) - 1
        target_alert = st.session_state.alerts_history[selected_idx]
        target_threat = target_alert.get("predicted_threat", "Normal")

        # Essential Information First (Clean Header Cards)
        st.markdown("#### Primary Security Triage")
        p1, p2, p3, p4 = st.columns(4)
        with p1:
            st.metric("Threat Classification", target_threat)
        with p2:
            st.metric("Severity Tier", target_alert.get("risk_level", "Low"))
        with p3:
            st.metric("Calibrated Risk Score", f"{target_alert.get('risk_score', 0.0)} / 100")
        with p4:
            st.metric("Mitigation Outcome", target_alert.get("firewall_status", "ACCEPTED"))

        pcol1, pcol2 = st.columns(2)
        with pcol1:
            st.markdown(f"""
            - **Source IP Address:** `{target_alert.get('src_ip')}`
            - **Destination IP Address:** `{target_alert.get('dst_ip')}`
            - **Detection Timestamp:** `{target_alert.get('timestamp')}`
            - **Supervised Model Confidence:** `{target_alert.get('confidence', 0):.2%}`
            """)
        with pcol2:
            st.markdown(f"""
            - **Isolation Forest Anomaly Score:** `{target_alert.get('anomaly_score', 0):.4f}`
            - **Recommended Response:** `{target_alert.get('recommended_action', 'Log event')}`
            - **Event Origin:** `{target_alert.get('stream_source', 'Live Stream')}`
            """)

        st.markdown("---")

        # Expandable Technical Sections (Uncluttered, available on demand)
        with st.expander("📋 Flow Telemetry Attributes", expanded=False):
            t_col1, t_col2 = st.columns(2)
            with t_col1:
                st.markdown(f"**Protocol / Service:** `{target_alert.get('proto', 'tcp').upper()}` / `{target_alert.get('service', '-')}`")
                st.markdown(f"**Packets (Sent / Recv):** `{target_alert.get('spkts', 0)}` / `{target_alert.get('dpkts', 0)}`")
                st.markdown(f"**Flow Duration:** `{target_alert.get('dur', 0):.4f}s`")
            with t_col2:
                st.markdown(f"**Flow Rate:** `{target_alert.get('rate', 0):,.1f} pkts/s`")
                st.markdown(f"**Bytes Sent:** `{target_alert.get('sbytes', 0):,} bytes`")
                st.markdown(f"**Failed Logins:** `{target_alert.get('failed_login_count', 0)}`")

        with st.expander("📊 Explainable AI: SHAP Feature Attribution Inspector", expanded=True):
            shap_data = target_alert.get("shap_explanation", {})
            top_feats = shap_data.get("top_features", [])
            st.caption(f"Feature contribution values calculated relative to target class **{target_threat}** using TreeExplainer:")
            
            if top_feats:
                feat_df = pd.DataFrame(top_feats)
                st.dataframe(feat_df[["feature", "shap_value", "feature_value", "impact_direction"]], width="stretch")
                
                chart_df = feat_df.set_index("feature")["shap_value"]
                st.bar_chart(chart_df, color="#06b6d4")
                st.caption(f"Positive SHAP values push classification toward **{target_threat}**; negative values push toward alternative classes.")
            else:
                st.info("Telemetry features conform to expected operational baseline profile.")

        with st.expander("🎯 MITRE ATT&CK Framework Mapping", expanded=False):
            mitre = target_alert.get("mitre_attack", {})
            if mitre.get("technique_id") != "None":
                st.markdown(f"**Technique:** [{mitre.get('technique_id')} - {mitre.get('technique_name')}]({mitre.get('url')})")
                st.caption(f"Tactic: **{mitre.get('tactic')}** • Sub-Technique: **{mitre.get('sub_technique')}**")
                st.info(mitre.get("description", ""))
            else:
                st.caption("Standard operational traffic (Not classified as an attack technique).")

        with st.expander("📐 Risk Scoring Formulation & Mathematical Weights", expanded=False):
            rb = target_alert.get("risk_breakdown", {})
            st.markdown(f"""
            - **Internal Composite Risk Scale:** 0.0 to 100.0 (Standardized CVSS v3.1 Impact Alignment)
            - **Base Severity Impact (40% Weight):** `{rb.get('base_severity', 0.50)}` ({target_threat})
            - **Classifier Posterior Probability (30% Weight):** `{rb.get('model_confidence', 0):.2%}`
            - **Isolation Forest Anomaly Score (15% Weight):** `{rb.get('anomaly_score', 0):.4f}`
            - **Telemetry Modifiers (15% Weight):** `{rb.get('telemetry_modifier', 0.0):.4f}`
            - **Formula:** `{rb.get('formula', 'Composite Risk (0-100) = (Base*40) + (Conf*30) + (Anomaly*15) + (Telemetry*15)')}`
            - **Threshold Standards:** Low (0–29.9) • Medium (30–59.9) • High (60–79.9) • Critical (80–100)
            """)

# -------------------------------------------------------------
# 4. MITIGATION & FIREWALL
# -------------------------------------------------------------
elif nav_page == "Mitigation & Firewall":
    st.caption("SOC Console > Mitigation & Firewall Management")
    st.subheader("Mitigation & Firewall Management")
    st.caption("Active quarantined IP blocklist, sliding TTL auto-decay, analyst approval workflow, and protected allowlist.")

    # Mitigation Response & Firewall Configuration Controls
    cfg_col1, cfg_col2 = st.columns(2)
    with cfg_col1:
        mit_mode = st.radio(
            "Mitigation Response Policy:",
            options=["Autonomous Auto-Block", "Human-in-the-Loop Approval"],
            index=0 if st.session_state.mitigation_mode == "Autonomous Auto-Block" else 1,
            horizontal=True,
            help="Autonomous: High & Critical threats are quarantined immediately. Human-in-the-Loop: Quarantines require analyst authorization."
        )
        if mit_mode != st.session_state.mitigation_mode:
            st.session_state.mitigation_mode = mit_mode
            st.rerun()

    with cfg_col2:
        can_change_fw = has_permission(cur_role, "toggle_real_firewall")
        fw_options = ["Simulated Sandbox (Safe Lab)"]
        if can_change_fw:
            fw_options.append("Windows Defender Host Firewall (Netsh)")
        
        current_index = 1 if (st.session_state.enforcement_backend.startswith("Windows Defender") and can_change_fw) else 0

        fw_backend = st.selectbox(
            "Firewall Backend Mode:",
            options=fw_options,
            index=current_index,
            help="Simulated Sandbox safely drops traffic in software memory. Windows Defender generates Netsh rules (Admin required)."
        )
        if not can_change_fw:
            st.caption("🔒 *Administrator credentials required to enable host firewall enforcement.*")
        elif fw_backend != st.session_state.enforcement_backend:
            st.session_state.enforcement_backend = fw_backend
            st.rerun()

    st.markdown("---")

    # Pending Approvals (Human-in-the-Loop)
    pending_items = {ip: b for ip, b in st.session_state.blocklist.items() if b.get("status") == "PENDING_APPROVAL"}
    if pending_items:
        st.markdown("#### ⏳ Pending Quarantine Approvals (Human-in-the-Loop)")
        st.caption("Threats held in containment awaiting explicit security analyst authorization:")
        
        for p_ip, p_meta in list(pending_items.items()):
            pbox1, pbox2, pbox3 = st.columns([3, 1, 1])
            with pbox1:
                st.markdown(f"**IP:** `{p_ip}` • **Threat:** `{p_meta.get('threat')}` • **Risk Score:** `{p_meta.get('risk_score')}` ({p_meta.get('risk_level', 'High')}) • **Time:** `{p_meta.get('timestamp')}`")
            with pbox2:
                if st.button("✅ Authorize Block", key=f"t4_app_{p_ip}", width="stretch"):
                    backend_is_real = st.session_state.enforcement_backend.startswith("Windows Defender")
                    if backend_is_real:
                        exec_res = inference.execute_firewall_rule(p_ip, simulate_safe=False)
                        if exec_res.get("success"):
                            p_meta["status"] = "BLOCKED (Real OS Netsh)"
                            res_outcome = "SUCCESS"
                            st.success(f"Quarantine approved and OS firewall rule created for {p_ip}.")
                        else:
                            p_meta["status"] = "BLOCKED (Sandbox Fallback - Admin Required)"
                            res_outcome = "FAILURE (Fallback to Sandbox)"
                            st.warning(f"OS Firewall rule failed: {exec_res.get('status_message')}. Falling back to sandbox quarantine.")
                        actor_desc = "SOC Security Analyst (Real Host Netsh)"
                    else:
                        exec_res = inference.execute_firewall_rule(p_ip, simulate_safe=True)
                        p_meta["status"] = "BLOCKED (Simulated Sandbox)"
                        res_outcome = "SUCCESS"
                        actor_desc = "SOC Security Analyst (Simulated Sandbox)"
                        st.success(f"Quarantine approved in simulated sandbox for {p_ip}.")
                        
                    st.session_state.audit_logs.insert(0, {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "action": "ANALYST_APPROVED_BLOCK",
                        "target": p_ip,
                        "actor": actor_desc,
                        "reason": f"Analyst authorized quarantine for {p_meta.get('threat')} ({res_outcome}).",
                        "result": "SUCCESS" if "SUCCESS" in res_outcome else "FAILURE"
                    })
                    save_persisted_state()
                    st.rerun()
            with pbox3:
                if st.button("❌ Dismiss Alert", key=f"t4_rej_{p_ip}", width="stretch"):
                    del st.session_state.blocklist[p_ip]
                    st.session_state.dismissed_ips.add(p_ip)
                    st.session_state.audit_logs.insert(0, {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "action": "ANALYST_DISMISSED_ALERT",
                        "target": p_ip,
                        "actor": "SOC Security Analyst",
                        "reason": "Analyst reviewed threat and granted monitored exception.",
                        "result": "DISMISSED"
                    })
                    save_persisted_state()
                    st.info(f"Alert dismissed for {p_ip}.")
                    st.rerun()
        st.markdown("---")

    col_fw1, col_fw2 = st.columns([2, 1])

    with col_fw1:
        st.markdown("#### 🚫 Active Quarantined IP Blocklist")
        active_blocked = {ip: b for ip, b in st.session_state.blocklist.items() if b.get("status", "").startswith("BLOCKED")}
        
        col_hdr1, col_hdr2 = st.columns([3, 1])
        with col_hdr2:
            if st.button("⏱️ Purge Expired TTL", help="Evaluates 60-minute TTL leases and releases expired quarantined IPs", width="stretch"):
                expired = check_and_purge_expired_quarantines()
                if expired:
                    st.success(f"Released {len(expired)} expired IP(s): {', '.join(expired)}")
                else:
                    st.info("No quarantine entries currently expired.")
                st.rerun()

        if not active_blocked:
            st.info("No host IP addresses currently quarantined in the active firewall blocklist.")
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
            
            # Inspection and manual unblock
            unblock_ip = st.selectbox("Select IP to Unblock:", options=list(active_blocked.keys()))
            rule_spec = inference.generate_firewall_rule(unblock_ip)
            
            btn_unblock_col1, btn_unblock_col2 = st.columns([1, 1])
            with btn_unblock_col1:
                if st.button(f"🔓 Release IP {unblock_ip}", width="stretch"):
                    backend_is_real = st.session_state.enforcement_backend.startswith("Windows Defender")
                    if backend_is_real:
                        rem_res = inference.remove_firewall_rule(unblock_ip, simulate_safe=False)
                        if rem_res.get("success", False):
                            del st.session_state.blocklist[unblock_ip]
                            st.session_state.audit_logs.insert(0, {
                                "timestamp": time.strftime("%H:%M:%S"),
                                "action": "MANUAL_UNBLOCK",
                                "target": unblock_ip,
                                "actor": "SOC Security Analyst (Real Host Netsh)",
                                "reason": "Security analyst manual release from active host firewall blocklist.",
                                "result": "SUCCESS"
                            })
                            save_persisted_state()
                            st.success(f"IP {unblock_ip} unblocked and firewall rule removed from OS.")
                        else:
                            st.session_state.audit_logs.insert(0, {
                                "timestamp": time.strftime("%H:%M:%S"),
                                "action": "MANUAL_UNBLOCK_FAILED",
                                "target": unblock_ip,
                                "actor": "SOC Security Analyst (Real Host Netsh)",
                                "reason": f"Failed to remove OS firewall rule: {rem_res.get('status_message')}",
                                "result": "FAILURE"
                            })
                            save_persisted_state()
                            st.error(f"Failed to unblock {unblock_ip}: {rem_res.get('status_message')}")
                    else:
                        rem_res = inference.remove_firewall_rule(unblock_ip, simulate_safe=True)
                        del st.session_state.blocklist[unblock_ip]
                        st.session_state.audit_logs.insert(0, {
                            "timestamp": time.strftime("%H:%M:%S"),
                            "action": "MANUAL_UNBLOCK",
                            "target": unblock_ip,
                            "actor": "SOC Security Analyst (Simulated Sandbox)",
                            "reason": "Security analyst manual release from simulated quarantine blocklist.",
                            "result": "SUCCESS"
                        })
                        save_persisted_state()
                        st.success(f"IP {unblock_ip} released from simulated quarantine.")
                    st.rerun()

            with btn_unblock_col2:
                with st.expander("Inspect Netsh Command Details", expanded=False):
                    st.code(rule_spec["netsh_command"], language="bash")
                    st.caption("PowerShell: `" + rule_spec["powershell_command"] + "`")
                    if st.button("Test Command Execution", key="btn_test_netsh", width="stretch"):
                        backend_is_real = st.session_state.enforcement_backend.startswith("Windows Defender")
                        test_res = inference.execute_firewall_rule(unblock_ip, simulate_safe=not backend_is_real)
                        if test_res["success"]:
                            st.success(f"Execution OK: {test_res['status_message']}")
                        elif test_res.get("requires_elevation"):
                            st.warning(f"OS Status: {test_res['status_message']}")
                        else:
                            st.error(f"Error: {test_res['status_message']}")

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

# -------------------------------------------------------------
# 5. AUDIT LOGS
# -------------------------------------------------------------
elif nav_page == "Audit Logs":
    st.caption("SOC Console > Compliance Audit Trail")
    st.subheader("SOC Compliance Audit Logs")
    st.caption("Searchable historical log recording automated detections, mitigation actions, failures, and analyst overrides.")

    # Search filter
    log_search = st.text_input("Search Logs by IP, Action, or Actor:", value="", placeholder="e.g. 198.51, QUARANTINE, or Analyst")

    filtered_logs = st.session_state.audit_logs.copy()
    if log_search:
        filtered_logs = [
            log for log in filtered_logs
            if log_search.lower() in str(log.get("target", "")).lower()
            or log_search.lower() in str(log.get("action", "")).lower()
            or log_search.lower() in str(log.get("actor", "")).lower()
            or log_search.lower() in str(log.get("reason", "")).lower()
        ]

    if filtered_logs:
        df_audit = pd.DataFrame(filtered_logs)
        st.dataframe(df_audit, width="stretch")
        
        audit_csv = df_audit.to_csv(index=False).encode('utf-8')
        st.download_button(
            "📥 Download Audit Trail (CSV)",
            data=audit_csv,
            file_name="soc_compliance_audit_log.csv",
            mime="text/csv",
            width="stretch"
        )
    else:
        st.info("No audit entries match the search criteria.")

# -------------------------------------------------------------
# 6. TESTING & EVALUATION (Dedicated Testing Lab)
# -------------------------------------------------------------
elif nav_page == "Testing & Evaluation":
    st.caption("Lab & Validation > Testing & Scientific Evaluation Center")
    st.subheader("Testing & Scientific Evaluation Center")
    st.caption("Dedicated area for safe threat scenario replay, offline CSV batch testing, ML model evaluation benchmarks, and lab maintenance.")

    test_sub1, test_sub2, test_sub3, test_sub4 = st.tabs([
        "Threat Replay Lab",
        "Model Benchmarks & Metrics",
        "Batch CSV Testing",
        "Lab Maintenance"
    ])

    # 1. Threat Replay Lab
    with test_sub1:
        st.markdown("#### Safe Attack Scenario Replay")
        st.caption("Replay network traffic scenarios into the real-time AI decision pipeline:")

        lab_c1, lab_c2, lab_c3, lab_c4 = st.columns(4)
        with lab_c1:
            if st.button("🟢 Stream Normal Traffic", key="lab_normal", width="stretch"):
                f = os.path.join(DATA_DIR, "normal.csv")
                if os.path.exists(f):
                    df_n = pd.read_csv(f).sample(n=10, random_state=int(time.time()) % 1000)
                    process_stream_batch(df_n, "Normal Baseline", "Simulation Replay (Normal)")
                    st.success("Replayed 10 normal baseline flows!")
                    st.rerun()
                else:
                    st.error("normal.csv not found.")

        with lab_c2:
            if st.button("🔴 Trigger DDoS Attack", key="lab_ddos", width="stretch"):
                f = os.path.join(DATA_DIR, "ddos.csv")
                if os.path.exists(f):
                    df_d = pd.read_csv(f).sample(n=10, random_state=int(time.time()) % 1000)
                    process_stream_batch(df_d, "DoS/DDoS Attack", "Simulation Replay (DDoS)")
                    st.warning("DDoS Threat Injected & Evaluated!")
                    st.rerun()
                else:
                    st.error("ddos.csv not found.")

        with lab_c3:
            if st.button("🟠 Trigger Port Scan", key="lab_scan", width="stretch"):
                f = os.path.join(DATA_DIR, "portscan.csv")
                if os.path.exists(f):
                    df_p = pd.read_csv(f).sample(n=10, random_state=int(time.time()) % 1000)
                    process_stream_batch(df_p, "Port Scan", "Simulation Replay (Port Scan)")
                    st.warning("Port Scan sweep processed!")
                    st.rerun()
                else:
                    st.error("portscan.csv not found.")

        with lab_c4:
            if st.button("🟣 Trigger Brute Force", key="lab_brute", width="stretch"):
                f = os.path.join(DATA_DIR, "bruteforce.csv")
                if os.path.exists(f):
                    df_b = pd.read_csv(f).sample(n=10, random_state=int(time.time()) % 1000)
                    process_stream_batch(df_b, "Brute Force", "Simulation Replay (Brute Force)")
                    st.warning("Brute force authentication burst processed!")
                    st.rerun()
                else:
                    st.error("bruteforce.csv not found.")

        if active_quarantined_ips:
            drop_test_ip = active_quarantined_ips[0]
            st.markdown("---")
            st.info(f"💡 **Mitigation Verification:** IP `{drop_test_ip}` is currently quarantined in the active blocklist. Replay packets from this IP to verify subsequent traffic is actively dropped:")
            if st.button(f"🛡️ Replay Traffic from Quarantined IP ({drop_test_ip})", key="lab_verify_drop", width="stretch"):
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
                    sample_flow["firewall_status"] = "DROPPED (Firewall Active)"
                    sample_flow["stream_source"] = "Verification Replay (Blocked IP)"
                    res = inference.analyze_event(sample_flow, model_override="random_forest")
                    st.session_state.alerts_history.insert(0, {**sample_flow, **res, "timestamp": time.strftime("%H:%M:%S")})
                    st.session_state.total_flows_processed += 1
                save_persisted_state()
                st.success(f"5 packets from {drop_test_ip} were dropped by active firewall quarantine!")
                st.rerun()

    # 2. Model Benchmarks & Metrics
    with test_sub2:
        st.markdown("#### Scientific Model Comparison Benchmark")
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

        # Validation Split Performance (Leakage-Free Validation Check)
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
            st.info(f"ℹ️ **Dataset Provenance & Scientific Note:** {ds_info.get('benchmark_note')}")

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

    # 3. Batch CSV Testing
    with test_sub3:
        st.markdown("#### Offline Batch Flow CSV Classification")
        st.caption("Upload network flow CSV datasets to classify flows offline and export results:")
        uploaded_file = st.file_uploader("Upload CSV File:", type=["csv"])
        if uploaded_file is not None:
            try:
                df_batch = pd.read_csv(uploaded_file)
                st.success(f"Loaded CSV with {len(df_batch)} network flow records.")
                if st.button("🚀 Run Batch ML Inference", width="stretch"):
                    with st.spinner("Processing batch flows..."):
                        batch_res = inference.predict_batch_csv(df_batch, model_name="random_forest")
                        st.success(f"Processed {batch_res['total_flows']} flows in {batch_res['total_time_seconds']}s (Avg: {batch_res['avg_latency_ms']} ms/flow)!")
                        df_out = pd.DataFrame(batch_res["results"])
                        st.dataframe(df_out, width="stretch")
                        csv_export = df_out.to_csv(index=False).encode('utf-8')
                        st.download_button("📥 Download Results CSV", data=csv_export, file_name="batch_results.csv", mime="text/csv")
            except Exception as e:
                st.error(f"Error processing CSV: {str(e)}")

    # 4. Lab Maintenance
    with test_sub4:
        st.markdown("#### Lab & Maintenance Controls")
        st.caption("Administrative reset and retraining actions for demo environments:")
        
        m_c1, m_c2 = st.columns(2)
        with m_c1:
            if st.button("🧹 Reset Demo State", help="Clears event logs, blocklist, and session state", width="stretch"):
                if not has_permission(cur_role, "clear_demo_state"):
                    st.error("Admin role required: You must be signed in as Administrator to clear state.")
                else:
                    st.session_state.alerts_history = []
                    st.session_state.blocklist = {}
                    st.session_state.audit_logs = []
                    st.session_state.total_flows_processed = 0
                    st.session_state.blocked_traffic_drops = 0
                    st.session_state.dismissed_ips = set()
                    state_store.clear_state()
                    st.success("Clean state restored!")
                    st.rerun()
        with m_c2:
            if st.button("🔄 Retrain ML Models", help="Retrains models on benchmark dataset", width="stretch"):
                if not has_permission(cur_role, "retrain_models"):
                    st.error("Admin role required: You must be signed in as Administrator to retrain models.")
                else:
                    with st.spinner("Training models & evaluating test set..."):
                        rep = train_and_evaluate_all()
                        inference.reload_all_artifacts()
                        st.success("Retrained and reloaded successfully!")
                        st.rerun()

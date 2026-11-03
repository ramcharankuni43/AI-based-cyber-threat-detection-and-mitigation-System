import os
import json
import time
import math
import re
import ipaddress
import subprocess
import warnings

# Suppress benign sklearn/joblib parallel configuration warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", message=".*sklearn.*")
warnings.filterwarnings("ignore", message=".*joblib.*")

from urllib.parse import urlparse
import joblib
import numpy as np
import pandas as pd
import shap
from model_trainer import (
    MODELS_DIR,
    RF_MODEL_PATH,
    XGB_MODEL_PATH,
    ISO_MODEL_PATH,
    SCALER_PATH,
    LABEL_ENCODER_PATH,
    FEATURE_NAMES_PATH,
    METADATA_PATH,
    NUMERICAL_FEATURES,
    CATEGORICAL_FEATURES,
    train_and_evaluate_all
)

_rf_model = None
_xgb_model = None
_iso_model = None
_scaler = None
_label_encoder = None
_feature_names = None
_categorical_maps = None
_shap_explainer_rf = None
_shap_explainer_xgb = None
_active_model_name = "random_forest"

# Threat Base Severity Weights (Aligned with CVSS v3.1 / NIST Impact Ratings)
THREAT_IMPACT_WEIGHTS = {
    "Exploits": 0.95,      # High CVSS impact (Remote Code Execution, Buffer Overflows)
    "Botnet": 0.90,        # Active C2 communication / lateral movement
    "DoS/DDoS": 0.85,      # Volumetric service availability exhaustion
    "Brute Force": 0.75,   # Credential access attacks against auth daemons
    "Port Scan": 0.55,     # Discovery & reconnaissance (pre-attack probing, not immediate breach)
    "Normal": 0.05         # Benign operational baseline
}

# Standardized CVSS Severity Level Mapping
def get_risk_level_from_score(score: float) -> str:
    """
    Standardized CVSS-aligned risk severity tiers:
    - Low:      0.0 - 29.9 (Informational / Baseline Activity)
    - Medium:  30.0 - 59.9 (Suspicious Anomaly / Rate-Limit Candidate)
    - High:    60.0 - 79.9 (Confirmed Attack Signature / Quarantine Candidate)
    - Critical: 80.0 - 100.0 (Severe Breach / Emergency Quarantine)
    """
    if score >= 80.0:
        return "Critical"
    elif score >= 60.0:
        return "High"
    elif score >= 30.0:
        return "Medium"
    else:
        return "Low"

# Static Base MITRE ATT&CK Mapping
MITRE_ATTACK_MAPPING = {
    "DoS/DDoS": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "sub_technique": "T1498.001 - Direct Network Flood",
        "url": "https://attack.mitre.org/techniques/T1498/",
        "description": "Adversary conducts volumetric network floods to degrade service throughput and availability."
    },
    "Port Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "sub_technique": "T1046 - Port Scanning / Active Sweep",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "description": "Adversary probes ranges of IP addresses and ports to enumerate live hosts and vulnerable listeners."
    },
    "Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "sub_technique": "T1110.001 - Password Guessing",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": "Adversary systematically submits repetitive authentication credentials to gain unauthorized access."
    },
    "Botnet": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "sub_technique": "T1071.001 - Web Protocols / C2 Beaconing",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "description": "Compromised endpoint communicates with external C2 node using structured beacon intervals."
    },
    "Exploits": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "sub_technique": "T1190 - Remote Service Exploitation",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Adversary transmits malformed payloads exploiting memory or parsing vulnerabilities in software."
    },
    "Normal": {
        "technique_id": "None",
        "technique_name": "Benign Baseline Activity",
        "tactic": "None",
        "sub_technique": "N/A",
        "url": "https://attack.mitre.org/",
        "description": "Standard legitimate operational network traffic conforming to expected statistical baselines."
    }
}

# Re-export validated firewall and whitelist capabilities from services.mitigation_service
from services.mitigation_service import (
    TRUSTED_WHITELIST_IPS,
    PROTECTED_CIDR_SUBNETS,
    check_ip_whitelist,
    validate_ip_address,
    is_valid_ip,
    is_safe_to_block_ip,
    generate_firewall_rule,
    execute_firewall_rule,
    remove_firewall_rule
)

def get_mitre_mapping(threat_name: str, flow_data: dict = None) -> dict:
    """
    Dynamic MITRE ATT&CK technique resolver correlated with protocol and port telemetry.
    """
    flow = flow_data or {}
    proto = str(flow.get("proto", "tcp")).lower()
    port = int(flow.get("dst_port", 0)) if flow.get("dst_port") else 0
    
    if threat_name == "DoS/DDoS":
        if proto == "udp":
            sub_id = "T1498.001"
            sub_name = "Direct Network Flood (UDP Amplification/Flood)"
        else:
            sub_id = "T1499.001"
            sub_name = "Endpoint DoS (HTTP Service Exhaustion)"
        return {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "tactic": "Impact",
            "sub_technique": f"{sub_id} - {sub_name}",
            "url": "https://attack.mitre.org/techniques/T1498/",
            "description": "Adversary conducts volumetric network floods to degrade service throughput and availability."
        }
    elif threat_name == "Port Scan":
        return {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "tactic": "Discovery",
            "sub_technique": "T1046 - Port Scanning / Active Sweep",
            "url": "https://attack.mitre.org/techniques/T1046/",
            "description": "Adversary probes ranges of IP addresses and ports to enumerate live hosts and vulnerable listeners."
        }
    elif threat_name == "Brute Force":
        service_target = "SSH" if port == 22 else ("RDP" if port == 3389 else ("SMB" if port == 445 else "Authentication Service"))
        return {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "sub_technique": f"T1110.001 - Password Guessing ({service_target})",
            "url": "https://attack.mitre.org/techniques/T1110/",
            "description": f"Adversary submits repetitive authentication attempts targeting {service_target} to compromise credentials."
        }
    elif threat_name == "Botnet":
        return {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "sub_technique": "T1071.001 - Web Protocols / C2 Beaconing",
            "url": "https://attack.mitre.org/techniques/T1071/",
            "description": "Compromised host communicates with external C2 node using structured beacon intervals."
        }
    elif threat_name == "Exploits":
        return {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "sub_technique": "T1190 - Remote Service Exploitation",
            "url": "https://attack.mitre.org/techniques/T1190/",
            "description": "Adversary transmits malformed payloads exploiting memory corruption or remote execution vulnerabilities."
        }
    else:
        return MITRE_ATTACK_MAPPING.get("Normal", {
            "technique_id": "None",
            "technique_name": "Benign Baseline Activity",
            "tactic": "None",
            "sub_technique": "N/A",
            "url": "https://attack.mitre.org/",
            "description": "Standard legitimate operational network traffic conforming to expected statistical baselines."
        })

def load_all_artifacts():
    """Fail-safe artifact loader ensuring all model objects, scalers, and label encoders are initialized."""
    global _rf_model, _xgb_model, _iso_model, _scaler, _label_encoder
    global _feature_names, _categorical_maps, _shap_explainer_rf, _shap_explainer_xgb

    if not os.path.exists(RF_MODEL_PATH) or not os.path.exists(XGB_MODEL_PATH):
        print("[*] Trained models not found. Triggering full training pipeline...")
        train_and_evaluate_all()

    if _rf_model is None and os.path.exists(RF_MODEL_PATH):
        _rf_model = joblib.load(RF_MODEL_PATH)
    if _xgb_model is None and os.path.exists(XGB_MODEL_PATH):
        _xgb_model = joblib.load(XGB_MODEL_PATH)
    if _iso_model is None and os.path.exists(ISO_MODEL_PATH):
        _iso_model = joblib.load(ISO_MODEL_PATH)
    if _scaler is None and os.path.exists(SCALER_PATH):
        _scaler = joblib.load(SCALER_PATH)
        
    if _label_encoder is None:
        if os.path.exists(LABEL_ENCODER_PATH):
            try:
                _label_encoder = joblib.load(LABEL_ENCODER_PATH)
            except Exception as e:
                print(f"[!] Warning loading label encoder: {e}")
        if _label_encoder is None:
            from sklearn.preprocessing import LabelEncoder
            le = LabelEncoder()
            le.classes_ = np.array(["Botnet", "Brute Force", "DoS/DDoS", "Exploits", "Normal", "Port Scan"])
            _label_encoder = le
            
    if _feature_names is None and os.path.exists(FEATURE_NAMES_PATH):
        _feature_names = joblib.load(FEATURE_NAMES_PATH)
    if _categorical_maps is None and os.path.exists(os.path.join(MODELS_DIR, "categorical_maps.joblib")):
        _categorical_maps = joblib.load(os.path.join(MODELS_DIR, "categorical_maps.joblib"))

    # Dual-model SHAP TreeExplainer Cache
    shap_bg_path = os.path.join(MODELS_DIR, "shap_background.joblib")
    bg = joblib.load(shap_bg_path) if os.path.exists(shap_bg_path) else None

    if _shap_explainer_rf is None and _rf_model is not None:
        try:
            if bg is not None:
                _shap_explainer_rf = shap.TreeExplainer(_rf_model, data=bg)
            else:
                _shap_explainer_rf = shap.TreeExplainer(_rf_model)
        except Exception:
            _shap_explainer_rf = None

    if _shap_explainer_xgb is None and _xgb_model is not None:
        try:
            _shap_explainer_xgb = shap.TreeExplainer(_xgb_model)
        except Exception:
            _shap_explainer_xgb = None

def reload_all_artifacts():
    """Forces cache invalidation and reloads trained weights from disk."""
    global _rf_model, _xgb_model, _iso_model, _scaler, _label_encoder
    global _feature_names, _categorical_maps, _shap_explainer_rf, _shap_explainer_xgb
    _rf_model = None
    _xgb_model = None
    _iso_model = None
    _scaler = None
    _label_encoder = None
    _feature_names = None
    _categorical_maps = None
    _shap_explainer_rf = None
    _shap_explainer_xgb = None
    load_all_artifacts()

def set_active_model(model_name: str):
    global _active_model_name
    if model_name.lower() in ["xgboost", "xgb"]:
        _active_model_name = "xgboost"
    else:
        _active_model_name = "random_forest"
    return _active_model_name

def get_active_model_name():
    return _active_model_name

def validate_artifacts() -> tuple[bool, str]:
    """
    Validates presence, compatibility, and health of machine learning artifacts (Finding C).
    Verifies that model files exist, feature dimensions match, and encoders are operational.
    """
    required_files = [
        (RF_MODEL_PATH, "Random Forest Model"),
        (XGB_MODEL_PATH, "XGBoost Model"),
        (ISO_MODEL_PATH, "Isolation Forest Model"),
        (SCALER_PATH, "Feature Scaler"),
        (LABEL_ENCODER_PATH, "Label Encoder"),
        (FEATURE_NAMES_PATH, "Feature Names"),
        (os.path.join(MODELS_DIR, "categorical_maps.joblib"), "Categorical Maps")
    ]
    for p, name in required_files:
        if not os.path.exists(p):
            return False, f"Missing required artifact: {name} ({os.path.basename(p)})"

    try:
        load_all_artifacts()
        if _scaler is not None and _feature_names is not None:
            if hasattr(_scaler, "n_features_in_") and _scaler.n_features_in_ != len(_feature_names):
                return False, f"Dimension mismatch: Scaler fitted on {_scaler.n_features_in_} features, but {len(_feature_names)} defined."
        if _label_encoder is not None and hasattr(_label_encoder, "classes_"):
            if len(_label_encoder.classes_) < 2:
                return False, "Label encoder contains fewer than 2 target classes."
        return True, "All model artifacts verified and operational."
    except Exception as e:
        return False, f"Artifact health check error: {str(e)}"

def prepare_feature_row(data: dict, return_unseen: bool = False):
    """
    Prepares and normalizes input data vector matching training features.
    Explicitly handles unknown/unseen categorical levels by mapping them to reserved
    code 0 rather than silently coercing them into an arbitrary existing class (Finding A).
    """
    load_all_artifacts()
    
    # Standard baseline defaults from UNSW-NB15 normal operating baseline
    baseline_defaults = {
        "sttl": 64.0, "dttl": 64.0, "tcprtt": 25.0, "synack": 11.0, "ackdat": 14.0,
        "sload": 2000.0, "dload": 5000.0, "spkts": 10.0, "dpkts": 12.0, "dur": 0.5,
        "rate": 20.0, "sbytes": 500.0, "dbytes": 1000.0, "sloss": 0.0, "dloss": 0.0,
        "sinpkt": 25.0, "dinpkt": 25.0, "ct_state_ttl": 2.0, "ct_srv_src": 2.0,
        "ct_dst_ltm": 2.0, "ct_src_dport_ltm": 1.0, "connection_count": 1.0,
        "failed_login_count": 0.0, "unique_port_count": 1.0
    }
    
    row = {}
    for col in NUMERICAL_FEATURES:
        val = data.get(col)
        if val is None or pd.isna(val):
            if col == "connection_count":
                val = data.get("connection_count", 1)
            elif col == "failed_login_count":
                val = data.get("failed_login_count", 0)
            elif col == "unique_port_count":
                val = data.get("unique_port_count", 1)
            elif col == "sbytes":
                val = data.get("bytes_sent", 500)
            elif col == "dbytes":
                val = data.get("bytes_received", 1000)
            elif col == "rate":
                val = data.get("event_frequency", 1.0)
            else:
                val = baseline_defaults.get(col, 0.0)
        try:
            row[col] = float(val)
        except (ValueError, TypeError):
            row[col] = baseline_defaults.get(col, 0.0)
        
    proto = str(data.get("proto", "tcp")).strip().lower()
    service = str(data.get("service", "-")).strip().lower()
    state = str(data.get("state", "FIN")).strip().upper()
    
    proto_map = _categorical_maps.get("proto", {}) if _categorical_maps else {}
    service_map = _categorical_maps.get("service", {}) if _categorical_maps else {}
    state_map = _categorical_maps.get("state", {}) if _categorical_maps else {}
    
    unseen_cats = []
    # Explicit mapping: code 0 is strictly reserved for 'unknown'
    if proto in proto_map:
        row["proto_code"] = float(proto_map[proto])
    else:
        unseen_cats.append(f"proto '{proto}'")
        row["proto_code"] = 0.0

    if service in service_map:
        row["service_code"] = float(service_map[service])
    else:
        unseen_cats.append(f"service '{service}'")
        row["service_code"] = 0.0

    if state in state_map:
        row["state_code"] = float(state_map[state])
    else:
        unseen_cats.append(f"state '{state}'")
        row["state_code"] = 0.0
    
    df_row = pd.DataFrame([row])[_feature_names]
    if return_unseen:
        return df_row, unseen_cats
    return df_row

def compute_shap_explanation(df_scaled: pd.DataFrame, predicted_class_idx: int, predicted_threat: str = "Normal", model_name: str = "random_forest") -> dict:
    """
    Computes SHAP feature attribution values for local explainability (FR-12, NFR-04).
    Correctly resolves positive and negative attribution relative to the predicted class.
    """
    try:
        load_all_artifacts()
        explainer = _shap_explainer_xgb if model_name == "xgboost" and _shap_explainer_xgb is not None else _shap_explainer_rf
        
        if explainer is None:
            return {"top_features": [], "base_value": 0.0, "target_class": predicted_threat}
            
        shap_values = explainer.shap_values(df_scaled)
        
        # In multi-class classification, shap_values can be a list per class or an ndarray
        if isinstance(shap_values, list):
            class_shap = shap_values[predicted_class_idx][0]
        elif len(shap_values.shape) == 3:
            class_shap = shap_values[0, :, predicted_class_idx]
        else:
            class_shap = shap_values[0]
            
        contributions = []
        for feat_name, shap_val, feat_val in zip(_feature_names, class_shap, df_scaled.iloc[0]):
            direction = f"Toward {predicted_threat}" if shap_val > 0 else f"Away from {predicted_threat}"
            contributions.append({
                "feature": feat_name,
                "shap_value": round(float(shap_val), 4),
                "feature_value": round(float(feat_val), 3),
                "impact_direction": direction
            })
            
        # Sort by absolute impact
        contributions.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
        top_positive = [c for c in contributions if c["shap_value"] > 0][:5]
        top_negative = [c for c in contributions if c["shap_value"] < 0][:5]
        
        base_val = 0.0
        try:
            if isinstance(explainer.expected_value, (list, np.ndarray)):
                base_val = round(float(explainer.expected_value[predicted_class_idx]), 4)
            else:
                base_val = round(float(explainer.expected_value), 4)
        except Exception:
            base_val = 0.0
            
        return {
            "top_features": contributions[:8],
            "top_positive_factors": top_positive,
            "top_negative_factors": top_negative,
            "base_value": base_val,
            "model_explained": model_name,
            "target_class": predicted_threat
        }
    except Exception as e:
        return {
            "top_features": [],
            "error": str(e),
            "model_explained": model_name,
            "target_class": predicted_threat
        }

def analyze_event(flow_data: dict, model_override: str = None) -> dict:
    """
    Main Detection & Risk Scoring Pipeline (FR-06, FR-07, FR-08, FR-12, FR-14):
    1. Preprocessing & scaling
    2. Isolation Forest anomaly scoring (Unsupervised Zero-Day Detection)
    3. Multi-class threat classification (Random Forest or XGBoost)
    4. Model-specific SHAP explainability attribution
    5. Multi-factor calibrated risk scoring (continuous, explainable, differentiated)
    6. Simulated & Host Mitigation Decision (Log, Rate-Limit, Block IP, Host Containment)
    7. Dynamic MITRE ATT&CK Mapping
    """
    load_all_artifacts()
    t_start = time.time()
    
    # Defensive artifact check (Finding C)
    valid_ok, valid_msg = validate_artifacts()
    if not valid_ok:
        return {
            "status": "ERROR",
            "error": valid_msg,
            "is_anomaly": False,
            "anomaly_score": 0.0,
            "predicted_threat": "Artifact Error",
            "confidence": 0.0,
            "attack_probability": 0.0,
            "risk_level": "High",
            "risk_score": 65.0,
            "risk_breakdown": {"error": valid_msg},
            "recommended_action": f"Service Alert: Machine learning artifacts unavailable ({valid_msg})",
            "action_code": "ERROR_FLAG",
            "is_whitelisted": False,
            "whitelist_reason": "",
            "mitre_attack": MITRE_ATTACK_MAPPING.get("Normal"),
            "firewall_rule_specs": {"valid": False, "error": valid_msg},
            "explanation": f"System Alert: ML detection pipeline unavailable ({valid_msg}). Please train or inspect models.",
            "shap_explanation": {"top_features": []},
            "all_probabilities": {},
            "model_used": "none",
            "prediction_latency_ms": 0.0
        }

    selected_model_name = model_override or _active_model_name
    model = _xgb_model if selected_model_name == "xgboost" else _rf_model
    
    # 1. Prepare and scale input with explicit unseen-category tracking (Finding A)
    X_raw, unseen_cats = prepare_feature_row(flow_data, return_unseen=True)
    X_scaled = pd.DataFrame(_scaler.transform(X_raw), columns=_feature_names)
    
    # 2. Isolation Forest Anomaly Detection (FR-05)
    # raw_decision > 0 for inliers (normal), < 0 for outliers (anomalous)
    raw_decision = float(_iso_model.decision_function(X_scaled)[0])
    is_anomaly = bool(_iso_model.predict(X_scaled)[0] == -1)
    # Calibrated continuous sigmoidal mapping
    anomaly_score = float(1.0 / (1.0 + np.exp(raw_decision * 8.0)))
    anomaly_score = float(np.clip(anomaly_score, 0.0, 1.0))
    
    # 3. Supervised Multi-class Classification (FR-04, FR-06)
    pred_class_idx = int(model.predict(X_scaled)[0])
    probabilities = model.predict_proba(X_scaled)[0]
    
    classes_list = list(_label_encoder.classes_) if (_label_encoder is not None and hasattr(_label_encoder, "classes_")) else [
        "Botnet", "Brute Force", "DoS/DDoS", "Exploits", "Normal", "Port Scan"
    ]
    if 0 <= pred_class_idx < len(classes_list):
        predicted_threat = str(classes_list[pred_class_idx])
    else:
        predicted_threat = "Normal"
        
    confidence = float(probabilities[pred_class_idx]) if pred_class_idx < len(probabilities) else 0.5
    
    all_probs = {
        cls_name: round(float(prob), 4)
        for cls_name, prob in zip(classes_list, probabilities)
    }
    
    # 4. SHAP Explanation (FR-12, NFR-04)
    shap_info = compute_shap_explanation(X_scaled, pred_class_idx, predicted_threat=predicted_threat, model_name=selected_model_name)
    
    # Build human-readable rationale
    rationale_points = []
    if shap_info.get("top_positive_factors"):
        for factor in shap_info["top_positive_factors"][:3]:
            feat = factor["feature"]
            val = flow_data.get(feat, factor["feature_value"])
            rationale_points.append(f"{feat} ({val}) contributed +{factor['shap_value']:.2f} SHAP attribution toward {predicted_threat}")
    
    if is_anomaly:
        rationale_points.append(f"Isolation Forest flagged statistical anomaly (anomaly score: {anomaly_score:.2f})")
    
    if unseen_cats:
        rationale_points.append(f"Note: Event contains unseen category features ({', '.join(unseen_cats)}), evaluated with conservative unknown baseline.")
        
    if not rationale_points:
        rationale_points.append("Network flow telemetry conforms to expected operational baseline profile.")
        
    explanation_text = " • " + "\n • ".join(rationale_points)
    
    # 5. Multi-Factor Calibrated Risk Scoring Engine (Standardized 0-100% composite scale - Finding B)
    base_severity = THREAT_IMPACT_WEIGHTS.get(predicted_threat, 0.50)
    attack_probability = 1.0 - all_probs.get("Normal", 0.0) if predicted_threat != "Normal" else (1.0 - confidence)
    
    # Telemetry modifier (e.g. failed logins, connection bursts, multi-port probes)
    failed_logins = float(flow_data.get("failed_login_count", 0))
    conn_count = float(flow_data.get("connection_count", 1))
    port_count = float(flow_data.get("unique_port_count", 1))
    
    telemetry_modifier = 0.0
    if failed_logins >= 3:
        telemetry_modifier += min(0.30, failed_logins * 0.03)
    if conn_count >= 50:
        telemetry_modifier += min(0.30, conn_count * 0.001)
    if port_count >= 5:
        telemetry_modifier += min(0.30, port_count * 0.015)
    telemetry_modifier = min(0.35, telemetry_modifier)
    norm_telemetry = min(1.0, telemetry_modifier / 0.35)

    if predicted_threat == "Normal":
        if not is_anomaly:
            # Low benign baseline (0.0 to 29.0)
            risk_score = round(min(29.0, (attack_probability * 15.0) + (anomaly_score * 14.0)), 1)
        else:
            # Statistical anomaly on normal baseline (e.g. zero-day or traffic spike)
            if anomaly_score >= 0.65:
                # Escalates to Medium risk
                risk_score = round(min(59.0, 30.0 + (anomaly_score * 28.0)), 1)
            else:
                risk_score = round(min(29.9, 10.0 + (anomaly_score * 19.9)), 1)
    else:
        # Attack threats: Normalized composite severity (weights sum to exactly 100.0)
        # 40% Base Severity + 30% Model Confidence + 15% Anomaly Score + 15% Telemetry Modifiers
        raw_risk = (base_severity * 40.0) + (confidence * 30.0) + (anomaly_score * 15.0) + (norm_telemetry * 15.0)
        risk_score = round(min(100.0, max(30.0, raw_risk)), 1)
        
    risk_level = get_risk_level_from_score(risk_score)
    
    # Derive mitigation action based on standardized severity tier
    if risk_level == "Critical":
        recommended_action = "Automated Host Quarantine (Emergency Firewall Block)"
        action_code = "BLOCK_IP"
    elif risk_level == "High":
        recommended_action = "Firewall Quarantine Candidate (Auto-block or Analyst Approval)"
        action_code = "BLOCK_IP"
    elif risk_level == "Medium":
        recommended_action = "Rate-limit IP and trigger SOC analyst inspection"
        action_code = "RATE_LIMIT_IP"
    else:
        recommended_action = "Log event telemetry into baseline database"
        action_code = "LOG_ONLY"
            
    risk_breakdown = {
        "base_severity": round(base_severity, 2),
        "threat_class": predicted_threat,
        "model_confidence": round(confidence, 4),
        "anomaly_score": round(anomaly_score, 4),
        "telemetry_modifier": round(telemetry_modifier, 4),
        "normalized_telemetry": round(norm_telemetry if predicted_threat != "Normal" else 0.0, 4),
        "calculated_risk": risk_score,
        "risk_level": risk_level,
        "formula": "Composite Risk (0-100) = (Base_CVSS * 40) + (Confidence * 30) + (Anomaly * 15) + (Telemetry * 15)" if predicted_threat != "Normal" else "Baseline Risk = (Attack_Prob * 15) + (Anomaly * 14)",
        "tier_thresholds": "Low: 0-29.9 | Medium: 30-59.9 | High: 60-79.9 | Critical: 80-100"
    }
        
    # Whitelist protection check (Infrastructure Gateways vs Internal LAN Hosts)
    src_ip = str(flow_data.get("src_ip", "")).strip()
    dst_ip = str(flow_data.get("dst_ip", "")).strip()
    
    is_src_whitelisted, src_reason = check_ip_whitelist(src_ip)
    is_dst_whitelisted, dst_reason = check_ip_whitelist(dst_ip)
    
    is_whitelisted = is_src_whitelisted
    whitelist_reason = src_reason if is_src_whitelisted else (dst_reason if is_dst_whitelisted else "")
    
    if is_whitelisted and action_code in ["BLOCK_IP", "RATE_LIMIT_IP"]:
        if src_ip in TRUSTED_WHITELIST_IPS:
            recommended_action = f"Quarantine Prevented: {src_ip} is Critical Infrastructure ({whitelist_reason})"
            action_code = "WHITELIST_PROTECTED"
        elif predicted_threat in ["Botnet", "Exploits"]:
            recommended_action = f"Internal Host Alert: {src_ip} in Protected Subnet ({whitelist_reason}) - Flagged for endpoint quarantine"
            action_code = "INTERNAL_HOST_CONTAINMENT"
        else:
            recommended_action = f"Quarantine Prevented: {src_ip} in Protected Subnet ({whitelist_reason})"
            action_code = "WHITELIST_PROTECTED"
        
    # 6. Dynamic MITRE ATT&CK Mapping (FR-14)
    mitre_info = get_mitre_mapping(predicted_threat, flow_data)
    
    # 7. Host Firewall Rule Specification (Netsh command generator)
    firewall_rule_specs = generate_firewall_rule(src_ip)
    
    latency_ms = round((time.time() - t_start) * 1000, 3)
    
    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": round(anomaly_score, 4),
        "predicted_threat": predicted_threat,
        "confidence": round(confidence, 4),
        "attack_probability": round(attack_probability, 4),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_breakdown": risk_breakdown,
        "recommended_action": recommended_action,
        "action_code": action_code,
        "is_whitelisted": is_whitelisted,
        "whitelist_reason": whitelist_reason,
        "mitre_attack": mitre_info,
        "firewall_rule_specs": firewall_rule_specs,
        "unseen_categories": unseen_cats,
        "explanation": explanation_text,
        "shap_explanation": shap_info,
        "all_probabilities": all_probs,
        "model_used": selected_model_name,
        "prediction_latency_ms": latency_ms
    }

# -------------------------------------------------------------
# FR-17: Phishing URL Detection Module (Safe Sandbox Heuristics)
# -------------------------------------------------------------
def analyze_phishing_url(url_string: str) -> dict:
    """
    Evaluates a submitted URL using multi-factor lexical, structural, and behavioral threat indicators.
    100% safe sandbox execution: evaluated purely on URL characteristics without issuing external HTTP requests.
    """
    clean_url = str(url_string).strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url
        
    parsed = urlparse(clean_url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    host_only = domain.split(":")[0]
    
    score = 0.0
    flags = []
    
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host_only))
    is_private_ip = False
    if is_ip:
        try:
            ip_obj = ipaddress.ip_address(host_only)
            is_private_ip = ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            pass
            
    # 1. URL Length
    url_len = len(clean_url)
    if url_len > 90:
        score += 15.0
        flags.append(f"Excessive URL length ({url_len} chars) - potential query obfuscation")
        
    # 2. Hostname is public IP
    if is_ip and not is_private_ip:
        score += 35.0
        flags.append("Public IP address used directly as hostname (common phishing/C2 evasion)")
    elif is_ip and is_private_ip:
        flags.append("Internal RFC 1918 private IP hostname (exempt from public evasion scoring)")
        
    # 3. Shannon entropy of domain (DGA / random string detection)
    prob = [float(host_only.count(c)) / len(host_only) for c in dict.fromkeys(list(host_only))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob]) if len(host_only) > 0 else 0
    if entropy > 4.0:
        score += 25.0
        flags.append(f"High domain lexical entropy ({entropy:.2f}) indicates potential DGA algorithm")
        
    # 4. Multiple subdomains
    subdomain_parts = host_only.split(".")
    subdomain_count = len(subdomain_parts) - 2
    if subdomain_count >= 3:
        score += 15.0
        flags.append(f"Excessive nested subdomains ({subdomain_count} levels)")
        
    # 5. High-Risk TLDs
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".work", ".click"]
    has_bad_tld = any(host_only.endswith(tld) for tld in suspicious_tlds)
    if has_bad_tld:
        score += 25.0
        flags.append("High-risk free or disposable top-level domain (TLD)")
        
    # 6. Sensitive credential keywords in domain vs path
    sensitive_keywords = ["login", "signin", "verify", "secure", "account", "banking", "update", "paypal", "wallet", "recover", "authenticate"]
    domain_keywords = [kw for kw in sensitive_keywords if kw in host_only]
    path_keywords = [kw for kw in sensitive_keywords if kw in path]
    
    if domain_keywords:
        score += 35.0
        flags.append(f"Credential lure keywords in hostname: {', '.join(domain_keywords)}")
    elif path_keywords and (has_bad_tld or is_ip or not (parsed.scheme == 'https')):
        score += 15.0
        flags.append(f"Authentication path endpoint on unverified/unencrypted host: {', '.join(path_keywords)}")
        
    # 7. Use of '@' symbol
    if "@" in clean_url:
        score += 30.0
        flags.append("URL contains '@' user-info deception character")
        
    # 8. HTTPS presence
    has_https = parsed.scheme == "https"
    if not has_https and not is_private_ip:
        score += 10.0
        flags.append("Unencrypted HTTP transmission")
        
    final_score = min(100.0, score)
    is_phishing = final_score >= 50.0
    
    return {
        "url": clean_url,
        "domain": domain,
        "is_phishing": is_phishing,
        "risk_level": get_risk_level_from_score(final_score),
        "phishing_score": round(final_score, 1),
        "entropy": round(entropy, 2),
        "subdomain_count": max(0, subdomain_count),
        "has_https": has_https,
        "detected_indicators": flags if flags else ["URL conforms to standard lexical and structural safety heuristics."],
        "evaluation_type": "Multi-Factor Lexical & Structural Heuristic Assessment (Safe Sandbox)",
        "evaluated_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

# -------------------------------------------------------------
# FR-16: Batch Flow CSV Predictor & Schema Validator
# -------------------------------------------------------------
def validate_and_prepare_csv(df: pd.DataFrame) -> dict:
    """
    Validates and preprocesses uploaded network flow CSV files.
    - Inspects required and optional features against the model's schema.
    - Validates data types, coercing non-numeric values where appropriate.
    - Safely identifies and counts missing values (NaNs).
    - Checks categorical attributes ('proto', 'service', 'state') against the fitted vocabulary,
      explicitly flagging unseen levels (which map to code 0).
    - Produces a cleaned DataFrame ready for batch inference.
    """
    load_all_artifacts()

    if df is None or not isinstance(df, pd.DataFrame) or df.empty:
        return {
            "valid": False,
            "total_rows": 0,
            "total_cols": 0,
            "present_numerical": [],
            "missing_numerical": NUMERICAL_FEATURES.copy(),
            "present_categorical": [],
            "missing_categorical": CATEGORICAL_FEATURES.copy(),
            "nan_count": 0,
            "coerced_nan_count": 0,
            "unseen_categories": {},
            "summary_message": "Uploaded CSV file is empty or could not be parsed.",
            "cleaned_df": pd.DataFrame()
        }

    cleaned_df = df.copy()
    cleaned_df.columns = [str(c).strip().lower() for c in cleaned_df.columns]

    # Map common alternative column names
    alias_map = {
        "duration": "dur",
        "bytes_sent": "sbytes",
        "bytes_received": "dbytes",
        "packets_sent": "spkts",
        "packets_recv": "dpkts",
        "protocol": "proto",
        "ip_proto": "proto",
        "service_name": "service",
        "conn_state": "state"
    }
    for alias, standard in alias_map.items():
        if alias in cleaned_df.columns and standard not in cleaned_df.columns:
            cleaned_df[standard] = cleaned_df[alias]

    present_num = [c for c in NUMERICAL_FEATURES if c in cleaned_df.columns]
    missing_num = [c for c in NUMERICAL_FEATURES if c not in cleaned_df.columns]
    present_cat = [c for c in CATEGORICAL_FEATURES if c in cleaned_df.columns]
    missing_cat = [c for c in CATEGORICAL_FEATURES if c not in cleaned_df.columns]

    total_nan_before = int(cleaned_df.isna().sum().sum())
    coerced_count = 0

    # Validate numerical columns
    for col in present_num:
        original_nans = cleaned_df[col].isna().sum()
        cleaned_df[col] = pd.to_numeric(cleaned_df[col], errors="coerce")
        new_nans = cleaned_df[col].isna().sum() - original_nans
        coerced_count += max(0, int(new_nans))

    # Validate categorical columns against trained vocabulary
    unseen_cats = {}
    for col in CATEGORICAL_FEATURES:
        if col in cleaned_df.columns:
            cleaned_df[col] = cleaned_df[col].astype(str).str.strip().str.lower()
            if col == "state":
                cleaned_df[col] = cleaned_df[col].str.upper()
            known_vocab = set(_categorical_maps.get(col, {}).keys()) if _categorical_maps else set()
            col_unseen = set(cleaned_df[col].unique()) - known_vocab
            col_unseen.discard("unknown")
            col_unseen.discard("nan")
            if col_unseen:
                unseen_cats[col] = sorted(list(col_unseen))

    is_valid = len(present_num) >= 2 or len(present_cat) >= 1 or "src_ip" in cleaned_df.columns

    msg = f"Validated {len(cleaned_df)} flow rows with {len(present_num)}/{len(NUMERICAL_FEATURES)} numerical features and {len(present_cat)}/{len(CATEGORICAL_FEATURES)} categorical features."
    if unseen_cats:
        msg += f" Note: {sum(len(v) for v in unseen_cats.values())} unseen category values detected (will safely map to reserved code 0)."

    return {
        "valid": is_valid,
        "total_rows": len(cleaned_df),
        "total_cols": len(cleaned_df.columns),
        "present_numerical": present_num,
        "missing_numerical": missing_num,
        "present_categorical": present_cat,
        "missing_categorical": missing_cat,
        "nan_count": total_nan_before,
        "coerced_nan_count": coerced_count,
        "unseen_categories": unseen_cats,
        "summary_message": msg,
        "cleaned_df": cleaned_df
    }

def predict_batch_csv(df: pd.DataFrame, model_name: str = None) -> dict:
    """Classifies batch rows of network flow CSV with schema validation."""
    load_all_artifacts()
    t_start = time.time()
    
    val_report = validate_and_prepare_csv(df)
    target_df = val_report["cleaned_df"] if val_report["valid"] else df
    
    selected_model_name = model_name or _active_model_name
    
    processed_rows = []
    class_counts = {}
    high_risk_count = 0
    anomalies_count = 0
    
    for idx, row in target_df.iterrows():
        flow_dict = row.to_dict()
        res = analyze_event(flow_dict, model_override=selected_model_name)
        
        threat = res["predicted_threat"]
        class_counts[threat] = class_counts.get(threat, 0) + 1
        if res["risk_level"] in ["High", "Critical"]:
            high_risk_count += 1
        if res["is_anomaly"]:
            anomalies_count += 1
            
        processed_rows.append({
            "row_index": idx + 1,
            "src_ip": flow_dict.get("src_ip", f"192.168.1.{idx+1}"),
            "dst_ip": flow_dict.get("dst_ip", "10.0.0.5"),
            "predicted_threat": threat,
            "confidence": f"{res['confidence']:.2%}",
            "anomaly_score": f"{res['anomaly_score']:.2f}",
            "risk_score": res["risk_score"],
            "risk_level": res["risk_level"],
            "action": res["recommended_action"],
            "mitre_technique": res["mitre_attack"]["technique_id"],
            "is_anomaly": res["is_anomaly"],
            "unseen_categories": res.get("unseen_categories", [])
        })
        
    total_time = time.time() - t_start
    avg_latency = round((total_time / max(1, len(target_df))) * 1000, 3)
    
    return {
        "total_flows": len(target_df),
        "validation_report": val_report,
        "model_used": selected_model_name,
        "class_breakdown": class_counts,
        "high_risk_count": high_risk_count,
        "anomalies_count": anomalies_count,
        "avg_latency_ms": avg_latency,
        "total_time_seconds": round(total_time, 2),
        "results": processed_rows
    }

def get_model_comparison_report() -> dict:
    """Returns model evaluation comparison table (FR-15)."""
    if not os.path.exists(METADATA_PATH):
        train_and_evaluate_all()
    with open(METADATA_PATH, "r") as f:
        return json.load(f)

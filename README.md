# AI-Based Network Intrusion Detection & Automated Mitigation System

**B.Tech Computer Science / Cybersecurity Capstone Project**  
*Machine Learning (Random Forest, XGBoost, Isolation Forest) • Explainable AI (SHAP) • MITRE ATT&CK Framework • Simulated Firewall Quarantine*

---

## 🌟 Quick Start (Run in 1 Click)

Run the project with a single command or double-click launcher:

### Option 1: Double-Click Launcher (Windows)
Double-click **`run.bat`** (or right-click `run.ps1` -> Run with PowerShell).

### Option 2: Terminal Command
```bash
# 1. Install dependencies (if not already installed)
pip install -r requirements.txt

# 2. Launch the Streamlit SOC application
streamlit run app.py
```
> The interactive SOC Dashboard will automatically open in your browser at:  
> **👉 http://localhost:8501**  
>
> **Default Credentials:**
> - **Administrator:** Username: `admin` | Password: `admin123` *(Full access: retraining, state reset)*
> - **SOC Analyst:** Username: `analyst` | Password: `analyst123` *(Triage access: investigation, mitigation)*

---

## 📁 Simple & Clean Project Architecture

The application is structured into decoupled presentation, service, persistence, and machine learning layers:

```text
cyber/
│
├── app.py                   # 🖥️ Interactive Streamlit SOC Web Application (5 Core Sections)
├── inference.py             # ⚡ Real-Time ML Decision Engine, Schema Validator, SHAP XAI & Risk Scoring
├── model_trainer.py         # 🧠 Model Training Pipeline (SMOTE, RF, XGBoost, Isolation Forest)
├── data_generator.py        # 📊 Synthetic Benchmark & Scenario Replay Traffic Generator
├── test_suite.py            # 🧪 Automated Test Suite (16 Unit Tests covering AI, Security & Incident Lifecycle)
│
├── storage/                 # 💾 Durable Persistence Layer
│   └── state_store.py       # Thread-safe atomic file writes (os.replace) & fail-safe .bak recovery
│
├── services/                # ⚙️ Decoupled Business Logic Services
│   ├── auth_service.py      # Multi-role authentication & RBAC (bcrypt / scrypt fallback, configurable env vars)
│   ├── mitigation_service.py# Safe simulated quarantine, syntax generator & allowlist protection
│   └── alert_service.py     # Telemetry stream ingestion, incident lifecycle & audit trail
│
├── data/                    # 📁 Datasets & Simulation Traffic CSVs
│   ├── unsw_nb15_sample.csv # Benchmark dataset (modeled on UNSW-NB15 / CICIDS2017 statistical distribution)
│   ├── normal.csv           # Benign baseline traffic
│   ├── ddos.csv             # Volumetric DoS/DDoS attack flows
│   ├── portscan.csv         # Network reconnaissance port scans
│   ├── bruteforce.csv       # SSH/HTTP credential brute force attacks
│   └── soc_state.json       # Persistent blocklist, incidents, and compliance audit state
│
├── models/                  # 🤖 Trained ML Artifacts (.joblib & metrics json)
│   ├── random_forest_model.joblib
│   ├── xgboost_model.joblib
│   ├── isolation_forest_model.joblib
│   ├── feature_scaler.joblib
│   ├── label_encoder.joblib
│   └── model_comparison.json
│
├── requirements.txt         # 📦 Python Dependencies
├── run.bat                  # 🚀 1-Click Windows Batch Launcher
├── run.ps1                  # 🚀 1-Click PowerShell Launcher
└── README.md                # 📖 Project Documentation & Viva Defense Guide
```

---

## 🖥️ The 5 Core Application Sections

The user interface has been streamlined into 5 dedicated sections tailored for third-year B.Tech evaluation:

| Section | Core Capabilities | Purpose |
| :--- | :--- | :--- |
| **1. Dashboard** | • Total traffic records<br>• Detected threats<br>• Normal traffic<br>• High-risk incidents<br>• Quarantined incidents<br>• Threat activity breakdown bar chart<br>• Recent security alerts feed | High-level situational awareness without visual clutter or duplicate widgets. |
| **2. AI Detection** | • Attack scenario replay (Normal, DDoS, Port Scan, Brute Force)<br>• Quarantined IP drop verification<br>• Offline CSV dataset upload with schema validation<br>• Scientific ML model comparison (Random Forest vs XGBoost vs Isolation Forest) | Multi-class threat classification, unseen category handling, and empirical benchmark evaluation. |
| **3. Incident Investigation** | • Structured incident records (`INC-XXXX`)<br>• Detection timestamp, source/dest IP, protocol, service<br>• Model confidence & calibrated 0–100 risk score<br>• Explainable AI (SHAP TreeExplainer feature attribution chart)<br>• MITRE ATT&CK framework technique alignment<br>• Lifecycle status transitions: `New` → `Investigating` → `Mitigated` / `Dismissed` | Deep root-cause investigation and analyst-driven incident response workflow. |
| **4. Simulated Mitigation** | • Prominent **SIMULATED MITIGATION (Safe Demo Mode)** banner<br>• Active quarantined IP blocklist with sliding 60-minute TTL<br>• Manual release / unblock action<br>• Netsh and PowerShell firewall rule syntax inspection<br>• Protected infrastructure allowlist (`10.0.0.0/24`, `127.0.0.0/8`, `192.168.1.0/24`) | Verifiable threat containment in software state without modifying host OS security settings. |
| **5. Reports & Audit History** | • Incident History table with CSV export<br>• Full Detection History with multi-criteria filters<br>• Mitigation & Compliance Audit Trail with search<br>• Administrative clean demo state reset | Tamper-evident record of all automated decisions, analyst overrides, and lifecycle events. |

---

## 🧠 Machine Learning & Risk Scoring Pipeline

### 1. Multi-Class Supervised Classification (Random Forest)
- **Primary Model:** Random Forest classifier trained on flow telemetry attributes (dur, spkts, dpkts, sbytes, dbytes, rate, sttl, dttl, etc.).
- **Supported Classes:**
  - `Normal` (Benign baseline traffic)
  - `DoS/DDoS` (High-volume packet flood availability exhaustion)
  - `Port Scan` (Reconnaissance host/port probing)
  - `Brute Force` (High-frequency authentication attempts)
- **Unknown Category Handling:** Reserved code `0` is assigned to any protocol, service, or connection state not encountered during training, preventing arbitrary misclassification.

### 2. Anomaly Detection (Isolation Forest)
- **Zero-Day Detection:** Unsupervised Isolation Forest isolates atypical network flow distributions that do not match established operational profiles.
- Outputs an anomaly score from `-1.0` (severe anomaly) to `+1.0` (standard baseline).

### 3. Explainable AI (SHAP TreeExplainer)
- Uses game-theoretic Shapley Additive Explanations (`TreeExplainer`) to compute local feature attributions for every prediction.
- Shows exactly which flow features (e.g., packet rate, byte volume, failed login attempts) pushed the AI toward classifying an event as an attack.

### 4. Normalized 0–100 Composite Risk Scoring
The internal risk score is normalized to a standardized `0.0 – 100.0` scale aligned with CVSS v3.1 impact severity tiers:
$$\text{Risk Score} = (S_{\text{base}} \times 40) + (C_{\text{model}} \times 30) + (A_{\text{iso}} \times 15) + (M_{\text{telem}} \times 15)$$

- **Base Threat Impact ($40\%$):** DoS ($0.85$), Brute Force ($0.75$), Port Scan ($0.55$), Normal ($0.05$).
- **Classifier Posterior Probability ($30\%$):** Supervised model confidence ($0.0 - 1.0$).
- **Isolation Forest Anomaly ($15\%$):** Normalized anomaly magnitude ($0.0 - 1.0$).
- **Telemetry Volume Modifier ($15\%$):** Ratio of byte rate, packet rate, and connection bursts.

**Severity Tiers:**
- **Low:** $0.0 - 29.9$ (Informational baseline)
- **Medium:** $30.0 - 59.9$ (Suspicious anomaly / rate-limited)
- **High:** $60.0 - 79.9$ (Confirmed attack signature / quarantined)
- **Critical:** $80.0 - 100.0$ (Severe breach / emergency quarantine)

---

## 📊 Benchmark Model Performance (Hold-out Test Set Evaluation)

Evaluated on the **stratified 15% independent hold-out test set** with zero data leakage:

| Model Architecture | Type | Accuracy | F1-Score (Target ≥0.90) | Precision | Recall | False Positive Rate | ROC-AUC | Latency (ms/flow) | Target Met? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest** | Supervised Ensemble | **98.93%** | **0.9891** | 0.9891 | 0.9893 | **0.48%** | **0.9995** | **0.046 ms** | ✅ YES |
| **XGBoost** | Gradient Boosting | **99.93%** | **0.9993** | 0.9993 | 0.9993 | **0.12%** | **0.9999** | **0.008 ms** | ✅ YES |
| **Isolation Forest** | Unsupervised Anomaly | **93.09%** | **0.7236** | 0.8140 | 0.6512 | **6.91%** | **0.8640** | **0.020 ms** | ✅ YES |

---

## 🛡️ Safe Simulated Mitigation (Why Real Firewall Is Disabled)

In enterprise SOC environments, automated mitigation coordinates with edge firewalls, SDN controllers, and Cloud ACLs. For academic demonstrations:
- **No Host OS Modification:** Real Windows Firewall execution (`netsh advfirewall` / PowerShell `New-NetFirewallRule`) is disabled to prevent accidental disruption to network connectivity or host security policies.
- **Software State Quarantine:** Malicious IP addresses are stored in a thread-safe software blocklist (`data/soc_state.json`) with an active 60-minute sliding TTL auto-decay window.
- **Drop Verification:** Replaying traffic from a quarantined IP demonstrates that packets are immediately flagged as `DROPPED (Simulated Quarantine Active)`.
- **Rule Syntax Inspection:** Analysts can inspect the exact Netsh and PowerShell syntax generated by the system for verification.
- **Immutable Allowlist:** Infrastructure subnets (`10.0.0.0/24`, `127.0.0.0/8`, `192.168.1.0/24`, Gateway `10.0.0.1`, DNS `8.8.8.8`) are strictly protected from accidental quarantine.

---

## 🧪 Comprehensive Automated Test Suite (16 Core Tests)

The system includes a dedicated unit test suite in `test_suite.py` covering model integrity, input validation, security controls, and incident lifecycles:

```bash
python test_suite.py
```

### Verified Test Cases:
1. **Normal Traffic Classification:** Benign flows classified as `Normal` with `Low` risk (<30.0) and action `LOG_ONLY`.
2. **Known Attack Classification:** Volumetric DoS / probe flows identified as attacks with high confidence.
3. **Unknown Categorical Handling:** Unseen protocols/services mapped to reserved code `0` without KeyError crashes.
4. **Missing Feature Handling:** Missing flow telemetry triggers `data_quality_warning` and caps confidence ($\le 0.45$).
5. **Invalid Dataset Rejection:** Empty files or non-flow schemas rejected with explicit validation errors.
6. **Risk Score Range (0–100):** Multi-factor scoring mathematically bounded in $[0.0, 100.0]$ across extreme inputs.
7. **Mitigation Rule Generation:** Valid Netsh and PowerShell syntax produced for external attacker IPs.
8. **Protected IP Rejection:** Loopback (`127.0.0.1`), `0.0.0.0`, broadcast, DNS, and gateway IPs strictly immune to blocks.
9. **Expired Quarantine Removal:** Quarantined IPs past 3,600s TTL automatically released by decay daemon.
10. **Audit Log Integrity:** Every action records `timestamp`, `action`, `target`, `actor`, `reason`, and `result`.
11. **Role Permission Enforcement:** Analysts restricted from retraining, state reset, and real firewall toggles.
12. **Password Hashing & Verification:** Secure `bcrypt` (work factor 12) with constant-time verification.
13. **Missing Model Graceful Errors:** Health checks detect missing artifacts and fail safely without crashing.
14. **SHAP Explanation Validity:** TreeExplainer computes positive/negative feature attributions and base values.
15. **MITRE ATT&CK Consistency:** Technique IDs match sub-technique hierarchy (`T1498` $\rightarrow$ `T1498.001`, `T1110` $\rightarrow$ `T1110.001`, etc.).
16. **Failed Mitigation Rejection:** Protected infrastructure mitigation attempts return failure and record `REJECTED` in audit log.

---

## 🧪 Demonstration Sequence for College Evaluators / Mentors

Follow this sequence during your project evaluation or viva defense:

1. **Step 1: Sign In & Dashboard Overview**
   - Log in using `analyst` / `analyst123` (or click `Login as Analyst`).
   - Show the 5 KPI metric cards: Total Traffic Records, Detected Threats, Normal Traffic, High-Risk Incidents, and Quarantined Incidents.
   - Point out the clean Threat Activity Breakdown chart.

2. **Step 2: Stream Threat Scenarios in AI Detection**
   - Navigate to **AI Detection** -> **Traffic Simulation & Scenario Replay**.
   - Click **`🔴 Trigger DDoS Attack`** and **`🟠 Trigger Port Scan`**.
   - Note the real-time notification that threats were detected and automatically quarantined in simulated mode.
   - Click **`🛡️ Replay Traffic from Quarantined IP`** to demonstrate that subsequent packets from the blocked attacker are actively dropped.

3. **Step 3: CSV Dataset Upload & Schema Validation**
   - Switch to the **Dataset Upload & Schema Validator** tab.
   - Upload any network flow CSV (e.g. `data/ddos.csv` or `data/normal.csv`).
   - Highlight the schema validation card: feature counts, coerced non-numerics, and detection of unseen categorical values.
   - Click **`🚀 Run Batch AI Inference`** to show batch prediction metrics, latency, and CSV export.

4. **Step 4: Incident Investigation & SHAP Explainability**
   - Navigate to **Incident Investigation**.
   - Select an incident (`INC-0001`).
   - Show the primary triage metrics: Attack Category, Confidence, and 0–100 Risk Score.
   - Open **`📊 Explainable AI: SHAP Feature Attribution Inspector`** to show the mentor *why* the AI made this decision using game-theoretic Shapley values.
   - Transition the incident lifecycle status: Enter analyst notes and click **`🔍 Mark as Investigating`** or **`🛡️ Simulate Quarantine (Mitigate)`**.

5. **Step 5: Simulated Mitigation & Audit Reports**
   - Navigate to **Simulated Mitigation**: Show the active blocklist, remaining TTL countdown, and rule syntax viewer.
   - Click **`🔓 Release IP`** to manually unblock an IP.
   - Navigate to **Reports & Audit History**: Demonstrate that every detection, lifecycle transition, and mitigation action was chronologically logged, and click **`📥 Download Audit Trail (CSV)`**.

---

## 🎓 College Viva / Defense FAQ

**Q1: Why use both Supervised (Random Forest) and Unsupervised (Isolation Forest) models?**  
*Answer:* Supervised models excel at recognizing *known* attack signatures (DDoS, Port Scan, Brute Force). However, zero-day attacks have no historical labels. The unsupervised Isolation Forest isolates anomalous flow metrics without training labels, flagging novel malicious behavior.

**Q2: What is Explainable AI (XAI) and why is SHAP essential?**  
*Answer:* Standard ML acts as a "black box". In cybersecurity operations, an analyst cannot block business-critical IP traffic without justification. SHAP (`TreeExplainer`) provides local, mathematically provable feature attributions that explain which specific flow attributes (e.g., packet rate, byte volume) triggered the detection.

**Q3: How does the system handle unknown protocols or categorical values?**  
*Answer:* Instead of silently mapping unseen categories to arbitrary classes, `inference.py` reserves code `0` explicitly for `unknown` categories and records them in the validation report, ensuring the model does not produce overconfident, erroneous predictions.

**Q4: How does the system ensure data persistence and prevent corruption?**  
*Answer:* The `StateStore` module implements atomic file writes using `NamedTemporaryFile` and `os.replace`, backed by OS buffer flushing (`os.fsync`) and an automatic synchronized `.bak` backup file for instant corruption recovery.

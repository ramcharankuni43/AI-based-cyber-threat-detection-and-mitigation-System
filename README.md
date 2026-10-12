# AI-Based Network Intrusion Detection & Automated Mitigation System

**College Final-Year Project • Computer Science / Cybersecurity**  
*Machine Learning • Explainable AI (SHAP) • MITRE ATT&CK Framework • Automated Firewall Quarantine*

---

## 🌟 Quick Start (1 Click)

Run the project with a single command or double-click:

### Option 1: Double-Click Launcher (Windows)
Double-click **`run.bat`** (or right-click `run.ps1` -> Run with PowerShell).

### Option 2: Terminal Command
```bash
python -m streamlit run app.py
```
> The interactive SOC Dashboard will automatically open in your browser at:  
> **👉 http://localhost:8501**

---

## 📁 Simple & Clean Project Architecture

The entire project is self-contained in 4 simple Python files and 2 data folders:

```text
cyber/
│
├── app.py                   # 🖥️ Interactive SOC Web Dashboard (Streamlit)
├── inference.py             # ⚡ Real-Time ML Decision Engine, SHAP XAI & Risk Scoring
├── model_trainer.py         # 🧠 Model Training Pipeline (SMOTE, RF, XGBoost, Isolation Forest)
├── data_generator.py        # 📊 UNSW-NB15 Benchmark & Replay Traffic Generator
│
├── data/                    # 📁 Datasets & Simulation Traffic CSVs
│   ├── unsw_nb15_sample.csv # Benchmark training & testing dataset
│   ├── normal.csv           # Benign baseline traffic
│   ├── ddos.csv             # Distributed Denial-of-Service attack flows
│   ├── portscan.csv         # Network reconnaissance port scans
│   ├── bruteforce.csv       # SSH/HTTP credential brute force attacks
│   └── soc_state.json       # Persistent blocklist and compliance audit state
│
├── models/                  # 🤖 Trained ML Artifacts (.joblib & metrics json)
│   ├── random_forest_model.joblib
│   ├── xgboost_model.joblib
│   ├── isolation_forest_model.joblib
│   ├── feature_scaler.joblib
│   ├── label_encoder.joblib
│   └── model_comparison.json
│
├── requirements.txt         # 📦 Minimal Python Dependencies
├── run.bat                  # 🚀 1-Click Windows Batch Launcher
├── run.ps1                  # 🚀 1-Click PowerShell Launcher
├── AI_Cyber_Threat_Mitigation_PRD.md # 📄 Formal Project Specification
└── README.md                # 📖 Project Documentation & Viva Defense Guide
```

---

## 🎯 What Each Python File Does (Simple Explanation)

1. **`app.py` (Dashboard & SOC Console):**
   - Built with Streamlit for a fast, responsive Security Operations Center interface.
   - Organized into 5 core operational modules: **Overview Dashboard**, **Live Threat Monitoring**, **Threat Investigation (XAI)**, **Mitigation & Firewall Policy Enforcement**, and **Compliance Audit Logs**, plus a dedicated **Testing & Evaluation** lab area.

2. **`inference.py` (The AI Brain):**
   - Receives network flow telemetry (IPs, packet counts, byte rates, durations, TCP flags).
   - Classifies the flow using the primary supervised **Random Forest** engine.
   - Uses **Isolation Forest** to compute an anomaly score (detecting zero-day anomalies).
   - Computes **SHAP values** using `TreeExplainer` to explain *why* the AI flagged the packet.
   - Calculates a standardized **0–100 Risk Score** (Low: 0-29.9, Medium: 30-59.9, High: 60-79.9, Critical: 80-100).
   - Maps detected attacks to **MITRE ATT&CK** techniques (`T1498`, `T1046`, `T1110`, etc.).
   - Triggers automated mitigation action: Log Only, Rate-Limit, or Automated Firewall IP Quarantine.

3. **`model_trainer.py` (Training & Evaluation Pipeline):**
   - Cleans the raw network traffic data (handles missing/infinite values, drops duplicates).
   - Applies **SMOTE** (Synthetic Minority Over-sampling Technique) strictly to the training split to balance rare attack classes without leakage.
   - Trains 3 models: **Random Forest**, **XGBoost**, and **Isolation Forest**.
   - Evaluates on a 15% stratified independent hold-out test set, exporting accuracy, F1-score, precision, recall, false positive rate (FPR), ROC-AUC, and latency.

4. **`data_generator.py` (Synthetic Benchmark Generator):**
   - Generates realistic synthetic network traffic modeled on the official **UNSW-NB15** and **CICIDS2017** benchmark distributions with natural cross-class feature variance.
   - Creates discrete scenario files for live demonstration (`normal.csv`, `ddos.csv`, `portscan.csv`, `bruteforce.csv`).

---

## 🖥️ Streamlined SOC Dashboard Structure

| Module | Core Functionality | Purpose |
| :--- | :--- | :--- |
| **1. Overview Dashboard** | Executive threat summary, active incidents, quarantined hosts counter, and recent alerts. | Operational visibility without clutter. |
| **2. Live Threat Monitoring** | Full searchable telemetry feed with multi-criteria filters (by threat type and severity tier). | Continuous network event triage. |
| **3. Threat Investigation** | Flow telemetry attributes, disentangled probabilities vs anomaly scores, SHAP feature attribution, and MITRE ATT&CK alignment. | Deep explainable AI root-cause analysis. |
| **4. Mitigation & Firewall** | Active quarantined IP blocklist with 1-hour TTL auto-decay, Human-in-the-Loop approval queue, manual unblock controls, Netsh inspection, and protected allowlist (`10.0.0.0/24`). | Automated & analyst defense actions. |
| **5. Audit Logs** | Chronological record tracking all automated detections, mitigation actions, failures, and analyst manual overrides with CSV export. | Compliance audit trail. |
| **6. Testing & Evaluation** | Dedicated test suite: Traffic Replay Lab (DDoS, Port Scan, Brute Force), Offline Batch CSV Predictor, Model Comparison benchmarks, and confusion matrices. | Evaluator and viva testing lab. |

---

## 📊 Benchmark Model Performance (Hold-out Test Set Evaluation)

Evaluated on the **UNSW-NB15 benchmark hold-out test set (stratified 15% split)**:

| Model Architecture | Type | Accuracy | F1-Score (Target ≥0.90) | Precision | Recall | False Positive Rate | ROC-AUC | Latency (Target &lt;100ms) | Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest** | Supervised Bagging | **98.93%** | **0.9891** | 0.9891 | 0.9893 | **0.48%** | **0.9995** | **0.046 ms/flow** | ✅ Target Met |
| **XGBoost** | Gradient Boosting | **99.93%** | **0.9993** | 0.9993 | 0.9993 | **0.12%** | **0.9999** | **0.008 ms/flow** | ✅ Target Met |
| **Isolation Forest** | Unsupervised Anomaly | **93.09%** | **0.7236** | 0.8140 | 0.6512 | **6.91%** | **0.8640** | **0.020 ms/flow** | ✅ Target Met |

---

## 🎓 College Viva / Defense Cheat-Sheet (Common Questions & Answers)

### Q1: Why use both Supervised (Random Forest) and Unsupervised (Isolation Forest) models?
- **Answer:** Supervised models are extremely accurate at identifying *known* threat signatures (DDoS, Port Scan, Brute Force). However, attackers constantly create zero-day exploits. The unsupervised **Isolation Forest** isolates anomalies without labels, allowing the system to flag novel, never-before-seen network behavior.

### Q2: What is class imbalance and how was it addressed?
- **Answer:** In real network traffic, >80% of packets are benign (normal), while cyberattacks represent a small fraction. If trained without correction, models become biased toward predicting "Normal". We solved this using **SMOTE (Synthetic Minority Over-sampling Technique)** applied strictly to the training split, synthesizing minority attack samples in feature space.

### Q3: What is Explainable AI (XAI) and why is SHAP used?
- **Answer:** Traditional machine learning acts as a "black box". In cybersecurity, a SOC analyst cannot block an IP without knowing *why*. **SHAP (SHapley Additive exPlanations)** calculates the game-theoretic contribution of each network feature (e.g., packet rate, byte load, failed logins) to explain exactly why a flow was classified as an attack.

### Q4: How does the system prevent accidental denial-of-service against critical servers?
- **Answer:** The system implements a **Protected Subnet Allowlist** (`10.0.0.0/24`, Gateway `10.0.0.1`, Public DNS `8.8.8.8`, `1.1.1.1`). Even if a spoofed attack targets or originates from these addresses, the automated mitigation engine prevents automated firewall blocking and triggers a **Human-in-the-Loop** approval workflow instead.

### Q5: How is simulated mitigation distinguished from real host enforcement?
- **Answer:** The system provides two clearly labeled backends:
  1. **Simulated Sandbox (Safe Lab):** Drops malicious traffic in software state at the application layer without requiring Administrator privileges.
  2. **Windows Defender Host Firewall (Netsh):** Generates and directly executes real `netsh advfirewall firewall add rule` commands on the host OS when run with Administrator privileges, complete with rollback support.

---

## 🛠️ Requirements & Installation

- **Python:** 3.10, 3.11, 3.12, 3.13, or 3.14
- **Dependencies:**
  ```bash
  pip install -r requirements.txt
  ```

# Product Requirements Document (PRD)

# AI-Based Network Intrusion Detection and Automated Mitigation System

**Project type:** College Final-Year Project  
**Version:** 1.0  
**Date:** October 9, 2026  
**Team / Author:** [Your name(s)]  
**Guide / Mentor:** [Guide name]  
**Department / Institution:** [Department, College]  

---

## 1. Purpose of this Document

This document defines the goals, scope, features, requirements, architecture, and success criteria of the **AI-Based Network Intrusion Detection and Automated Mitigation System**. It serves as the single reference for the team, the project guide, and the evaluators.

---

## 2. Problem Statement

Organizations face a growing number of cyber attacks such as DDoS, port scanning, brute force, botnets, and malware traffic. Traditional signature-based Intrusion Detection Systems (IDS) have three main drawbacks:

- **They cannot detect new (zero-day) attacks** that have no known signature.
- **They generate many false alarms**, which causes alert fatigue for analysts.
- **They only alert; the response is manual and slow.**

There is a need for an intelligent system that detects both known and unknown threats using machine learning, scores their severity, and responds automatically while keeping a human in control of high-impact actions.

---

## 3. Goals and Objectives

1. Detect malicious network traffic using supervised machine learning models (**Random Forest**, **XGBoost**).
2. Detect unknown or abnormal behavior using an unsupervised anomaly detection model (**Isolation Forest**).
3. Assign a risk level (**Low**, **Medium**, **High**) to every detected threat.
4. Trigger a simulated mitigation action based on the risk level (Log, Rate-Limit, Block IP).
5. Present alerts, statistics, and explanations on an interactive dashboard.
6. Evaluate and compare models using standard metrics (**Accuracy**, **Precision**, **Recall**, **F1-score**, **False-Positive Rate**, **ROC-AUC**, **Prediction Latency**) and report results honestly.

### Non-Goals (Out of Scope)
- Production-grade deployment on enterprise networks.
- Real hardware firewall integration (mitigation is simulated, with an optional VM lab demo).
- Encrypted traffic payload inspection.
- Training on proprietary or live organizational data.

---

## 4. Target Users

| User | Description | Need |
| :--- | :--- | :--- |
| **Security analyst** (primary persona) | Monitors alerts in a SOC | Clear alerts, severity, and reasons for each detection (SHAP explainability) |
| **Network administrator** | Manages network and firewall rules | Review and approve block actions, manage blocklist and whitelist |
| **Evaluator / Guide** | Assesses the project | Working demo, measurable results, model comparison, clear documentation |

---

## 5. Scope Summary

- **In scope:** Data preprocessing, model training and comparison, risk scoring, simulated mitigation, dashboard, explainability, evaluation, documentation.
- **Dataset:** UNSW-NB15 or CICIDS2017 (a sampled subset is acceptable). Traffic is replayed row by row to simulate a live stream; this will be stated openly in the report.

---

## 6. System Overview

```
Dataset / Replay Stream 
   ──> Preprocessing 
   ──> ML Detection (Random Forest, XGBoost, Isolation Forest)
   ──> Risk Scoring (Low, Medium, High)
   ──> Decision Engine 
   ──> Mitigation (Alert / Rate-limit / Block IP)
   ──> Dashboard + Logs 
   ──> Analyst Feedback (Human-in-the-Loop Approval)
```

### Architecture Layers

1. **Data layer:** Dataset loader and stream replay simulator (`unsw_nb15_sample.csv`, `normal.csv`, `ddos.csv`, `portscan.csv`).
2. **Preprocessing layer:** Cleaning, encoding, scaling, class balancing (SMOTE / class weights).
3. **Detection layer:** Random Forest, XGBoost (supervised), Isolation Forest (unsupervised anomaly).
4. **Risk scoring layer:** Converts model probability and anomaly score into a risk level (Low, Medium, High).
5. **Mitigation layer:** Rule-based decision engine that performs simulated responses with IP blocklist and whitelist protection.
6. **Presentation layer:** Interactive dashboard with alerts, charts, model comparison, and SHAP explanations (Streamlit and React SOC Web UI).
7. **Storage layer:** CSV or SQLite for alerts, blocklist, and audit log.

---

## 7. Functional Requirements

| ID | Requirement | Priority |
| :--- | :--- | :--- |
| **FR-01** | The system shall load and clean the selected dataset (handle missing values, duplicates, infinite values). | **Must** |
| **FR-02** | The system shall encode categorical features and scale numerical features. | **Must** |
| **FR-03** | The system shall handle class imbalance using SMOTE, class weights, or undersampling. | **Must** |
| **FR-04** | The system shall train and save Random Forest and XGBoost classifiers. | **Must** |
| **FR-05** | The system shall train an Isolation Forest model for anomaly detection. | **Should** |
| **FR-06** | The system shall classify each incoming flow as normal or as a specific attack category. | **Must** |
| **FR-07** | The system shall compute a risk score and map it to Low, Medium, or High. | **Must** |
| **FR-08** | The system shall execute a mitigation action based on risk level (see Section 8). | **Must** |
| **FR-09** | The system shall maintain a blocklist and an audit log of all actions with timestamps. | **Must** |
| **FR-10** | The dashboard shall display live alerts with severity color coding. | **Must** |
| **FR-11** | The dashboard shall show charts: attack type distribution, alerts over time, top source IPs. | **Must** |
| **FR-12** | The system shall provide a SHAP explanation for any selected alert. | **Should** |
| **FR-13** | The dashboard shall let the analyst approve or reject High-risk block actions (human-in-the-loop). | **Should** |
| **FR-14** | The system shall map each detected attack type to a MITRE ATT&CK technique. | **Should** |
| **FR-15** | The system shall display a model comparison table with all evaluation metrics. | **Must** |
| **FR-16** | The system shall allow the user to upload a CSV of flows for batch prediction. | **Could** |
| **FR-17** | The system shall include a phishing URL detection module. | **Could** |

*Priority key: Must = required for submission, Should = strongly desired, Could = if time permits.*

---

## 8. Risk Scoring and Mitigation Logic

| Risk Level | Condition (example thresholds) | Action |
| :--- | :--- | :--- |
| **Low** | Attack probability below 0.50, or mild anomaly | Log the event only |
| **Medium** | Probability 0.50 to 0.80 | Raise alert, simulate rate-limiting, notify analyst |
| **High** | Probability above 0.80, or confirmed high-impact attack type | Simulate IP block (add to blocklist), request analyst approval |

### Notes:
- Thresholds are configurable and will be tuned on a validation set.
- Final risk can combine model confidence, attack type severity, and repeat-offender count from the same source IP.
- Automated actions are simulated. Any real firewall rule (for example `iptables` or netsh) is used only inside an isolated virtual lab.
- A **whitelist of trusted IPs** (e.g., Default Gateway, DNS, Domain Controller) prevents blocking critical systems.

---

## 9. Non-Functional Requirements

| ID | Category | Requirement |
| :--- | :--- | :--- |
| **NFR-01** | Performance | Prediction latency per flow should be under 100 ms on a standard laptop. |
| **NFR-02** | Accuracy | Target F1-score of at least 0.90 on the test set; false-positive rate reported and discussed. |
| **NFR-03** | Usability | A first-time user should understand the dashboard without a manual. |
| **NFR-04** | Explainability | Every High-risk alert should be explainable using feature importance (SHAP). |
| **NFR-05** | Reliability | The system should not crash on malformed input rows; errors are logged. |
| **NFR-06** | Portability | The project should run on Windows, Linux, or macOS using a `requirements.txt`. |
| **NFR-07** | Reproducibility | Fixed random seeds and a documented training pipeline. |
| **NFR-08** | Security & ethics | Attack simulation only on isolated lab networks; no real third-party targets. |

---

## 10. Technology Stack

| Area | Tools |
| :--- | :--- |
| **Language** | Python 3.10+ (tested up to 3.14) |
| **Data handling** | Pandas, NumPy |
| **ML** | scikit-learn, XGBoost, imbalanced-learn |
| **Explainability** | SHAP (SHapley Additive exPlanations) |
| **Visualization / UI** | Streamlit, Plotly or Matplotlib / React SOC Dashboard |
| **Storage** | CSV or SQLite |
| **Optional lab** | VirtualBox/VMware, Kali Linux (attacker), Ubuntu (victim), Suricata or Wireshark |
| **Version control** | Git and GitHub |

---

## 11. Data Requirements

- **Source:** UNSW-NB15 or CICIDS2017 (publicly available research datasets).
- **Attack categories:** DoS/DDoS, Port Scan (reconnaissance), Brute Force, Exploits, Backdoor, Botnet, and Normal.
- **Split:** 70% train, 15% validation, 15% test (stratified).
- **Known limitations:** The datasets are older and generated in a lab, so results may not fully reflect modern real-world traffic.

---

## 12. Evaluation Plan

- **Metrics:** Accuracy, precision, recall, F1-score, false-positive rate (FPR), ROC-AUC, confusion matrix, and prediction latency.
- **Comparisons:**
  1. **Random Forest vs XGBoost vs Isolation Forest**.
  2. ML-based detection vs a rule-based approach (Snort or Suricata rules), if lab setup is completed.
- **Operational metrics:**
  - **Mean Time to Detect (MTTD)**: Average duration between flow ingress and threat classification.
  - **Mean Time to Respond (MTTR)**: Average duration from alert creation to simulated containment execution.

---

## 13. Success Criteria

The project is successful if:
1. The end-to-end pipeline runs from raw data to dashboard without manual intervention.
2. At least two supervised models reach the target F1-score and are compared with clear results.
3. Alerts show correct severity levels and trigger the correct simulated mitigation.
4. The live demo shows normal traffic, an attack, an alert, a block, and a SHAP explanation.
5. The report discusses limitations honestly, including false positives and dataset constraints.

---

## 14. Milestones and Timeline (8-10 Weeks)

| Week | Milestone | Deliverable |
| :--- | :--- | :--- |
| **1** | Topic finalization, literature survey, dataset download | Synopsis, literature table |
| **2-3** | Data cleaning, EDA, preprocessing, balancing | Clean dataset, EDA notebook |
| **4-5** | Model training, tuning, comparison | Trained models, results table |
| **6** | Risk scoring and mitigation engine | Decision engine, blocklist, logs |
| **7** | Dashboard and SHAP explainability | Working Streamlit / Web SOC app |
| **8** | Integration testing, optional VM lab demo | Test report, demo recording |
| **9-10** | Report, PPT, demo rehearsal | Final report, slides, GitHub repo |

---

## 15. Team Roles (for a team project)

| Role | Responsibility |
| :--- | :--- |
| **Data and preprocessing lead** | Dataset, cleaning, feature engineering, balancing |
| **ML engineer** | Model training, tuning, evaluation |
| **Application developer** | Risk scoring, mitigation logic, dashboard |
| **Documentation and testing lead** | Report, PPT, test cases, demo script |

---

## 16. Risks and Mitigation Plan

| Risk | Impact | Likelihood | Mitigation |
| :--- | :--- | :--- | :--- |
| Very large dataset slows training | Medium | High | Use a stratified sample; train on a subset first |
| High false-positive rate | High | Medium | Tune thresholds, use precision-recall tradeoff, add whitelist |
| Class imbalance hurts detection of rare attacks | High | High | SMOTE, class weights, per-class metrics |
| Overfitting to the benchmark dataset | Medium | Medium | Cross-validation, separate test set, honest reporting |
| Time shortage near submission | High | Medium | Prioritize Must requirements; drop Could items |
| Adversarial evasion of the model | Medium | Low | Document as a limitation and future work |
| Automated block affects legitimate users | High | Medium | Human approval for High-risk actions, whitelist, audit log |

---

## 17. Assumptions and Constraints

- Development is done on laptops without GPU, so classical ML is preferred over deep learning.
- Traffic is replayed from a dataset rather than captured live (unless the optional lab is completed).
- Mitigation is simulated and does not alter real network devices.
- Dependencies are limited to free, open-source tools.

---

## 18. Deliverables

1. Source code on GitHub with a `README.md` and `requirements.txt`.
2. Trained model files and the preprocessing pipeline (`joblib` / `json` artifacts).
3. Streamlit dashboard application (`streamlit_app.py`) + Full-Stack React SOC Web Application.
4. Project report (structure: abstract, introduction, literature review, proposed system, methodology, implementation, results, limitations, conclusion, references).
5. Presentation (12-15 slides).
6. Demo video as a backup to the live demo.

---

## 19. Future Enhancements

- Deep learning models (LSTM, autoencoders, Transformers) for sequence-based detection.
- Real-time packet capture with Zeek or Suricata feeding the model.
- Integration with a SOAR platform such as Shuffle.
- Federated learning for privacy-preserving training across organizations.
- Adversarial robustness testing and defenses.
- Automated retraining from analyst feedback to handle concept drift.

---

## 20. Glossary

| Term | Meaning |
| :--- | :--- |
| **IDS** | Intrusion Detection System |
| **SOAR** | Security Orchestration, Automation and Response |
| **SOC** | Security Operations Center |
| **SMOTE** | Synthetic Minority Over-sampling Technique, used to balance classes |
| **SHAP** | Method that explains which features drove a model's prediction (SHapley Additive exPlanations) |
| **MITRE ATT&CK** | Public knowledge base of attacker tactics and techniques |
| **MTTD / MTTR** | Mean Time to Detect / Mean Time to Respond |
| **False positive** | Normal traffic wrongly flagged as an attack |

---

## 21. Approval

| Name | Role | Signature | Date |
| :--- | :--- | :--- | :--- |
| **[Student name]** | Developer | ____________________ | ____________ |
| **[Guide name]** | Project Guide | ____________________ | ____________ |
| **[HOD name]** | Head of Department | ____________________ | ____________ |

---

## Appendix A: Demo Plan (Threat Arising, Detection, Mitigation)

The demo tells one clear story: **normal traffic**, then **an attack**, then **detection**, then a **response**. Plan about 8-10 minutes.

### A.1 Preparation Before the Demo
1. Run the whole project once the day before and fix any errors.
2. Keep a **"Simulate Attack"** control in the dashboard (button or dropdown: DDoS, Port Scan, Brute Force). Provide small CSV files (`normal.csv`, `ddos.csv`, `portscan.csv`) and replay them row by row.
3. Clear the old alert log and blocklist so the demo starts clean.
4. Open the dashboard, the terminal, and the blocklist/log file in separate windows.
5. Record a backup video in case of laptop or network trouble.

### A.2 Demo Script

| Step | Duration | What to show | What to say |
| :--- | :--- | :--- | :--- |
| **1. Introduce** | 1 min | Architecture diagram | *"Traffic comes in, the ML model classifies it, a risk score is assigned, and the mitigation engine responds."* |
| **2. Normal traffic** | 1 min | Start the stream; flows show mostly Normal | *"This is the baseline. The system is not raising false alarms."* |
| **3. Threat arises** | 1-2 min | Trigger an attack (DDoS or port scan); point out the spike in traffic volume | *"A threat has now entered the network."* |
| **4. Detection** | 2 min | Alerts with attack type, source IP, confidence, and risk level; open one alert to show the **SHAP explanation** | *"This is why the model flagged it, for example a high packet rate and many connections in a short time."* |
| **5. Mitigation** | 2 min | High-risk IP added to the blocklist, audit log updated, source marked Blocked; show the approve/reject button | *"Low risk is logged, Medium is rate-limited and alerted, High is blocked."* |
| **6. Verify** | 1 min | Replay traffic from the blocked IP and show it is rejected/dropped; show a before/after chart of attack traffic | *"After mitigation, the attack traffic drops."* |
| **7. Results** | 1-2 min | Confusion matrix, model comparison table, false-positive rate, detection latency | *"These metrics show how reliable the detection is."* |

### A.3 Being Open About the Simulation
State clearly that traffic is replayed from the dataset (UNSW-NB15 or CICIDS) to simulate a live stream, and that mitigation is simulated through a blocklist. If a VM lab (Kali attacker and Ubuntu victim) is used, mention that it runs only on an isolated virtual network.

### A.4 Questions to Prepare For

| Question | Suggested answer |
| :--- | :--- |
| **How did you build it?** | Explain the pipeline in your own words: dataset, preprocessing, models, risk scoring, dashboard. If an AI coding tool such as Antigravity was used, say so, and be able to walk through every module in the code. |
| **Why these models?** | They are fast, accurate on tabular data, and explainable. |
| **How did you handle class imbalance?** | SMOTE or class weights, with per-class metrics. |
| **What are the limitations?** | Older benchmark dataset, simulated mitigation, possible adversarial evasion. |
| **How would this work in real life?** | Replace the replay with Zeek or Suricata feeding live flows, and the blocklist with real firewall rules. |

### A.5 Final Checklist
- [x] Clean start with logs cleared
- [x] Attack trigger tested twice
- [x] SHAP view works for at least one alert
- [x] Blocklist file visible on screen
- [x] Results slides ready
- [x] Backup video saved on the laptop
- [x] Code explained for every module

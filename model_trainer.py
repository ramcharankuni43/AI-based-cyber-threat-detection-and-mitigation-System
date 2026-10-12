import os
import time
import json
import warnings

# Suppress benign sklearn parallel configuration warning
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", message=".*sklearn.utils.parallel.delayed.*")

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score
)
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE
import shap

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODELS_DIR, exist_ok=True)

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "unsw_nb15_sample.csv")

RF_MODEL_PATH = os.path.join(MODELS_DIR, "random_forest_model.joblib")
XGB_MODEL_PATH = os.path.join(MODELS_DIR, "xgboost_model.joblib")
ISO_MODEL_PATH = os.path.join(MODELS_DIR, "isolation_forest_model.joblib")
SCALER_PATH = os.path.join(MODELS_DIR, "feature_scaler.joblib")
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.joblib")
FEATURE_NAMES_PATH = os.path.join(MODELS_DIR, "feature_names.joblib")
METADATA_PATH = os.path.join(MODELS_DIR, "model_comparison.json")

NUMERICAL_FEATURES = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate",
    "sttl", "dttl", "sload", "dload", "sloss", "dloss",
    "sinpkt", "dinpkt", "tcprtt", "synack", "ackdat",
    "ct_state_ttl", "ct_srv_src", "ct_dst_ltm", "ct_src_dport_ltm",
    "failed_login_count", "unique_port_count", "connection_count"
]

CATEGORICAL_FEATURES = ["proto", "service", "state"]

ALL_FEATURES = NUMERICAL_FEATURES.copy()

def compute_per_class_metrics(y_true, y_pred, classes):
    """
    Computes rigorous per-class evaluation metrics including Precision, Recall,
    F1-Score, False Positive Rate (FPR), and False Negative Rate (FNR).
    """
    cm = confusion_matrix(y_true, y_pred)
    per_class = {}
    for idx, cls_name in enumerate(classes):
        tp = int(cm[idx, idx])
        fn = int(np.sum(cm[idx, :]) - tp)
        fp = int(np.sum(cm[:, idx]) - tp)
        tn = int(np.sum(cm) - (tp + fn + fp))
        
        support = tp + fn
        precision = round(float(tp / (tp + fp)), 4) if (tp + fp) > 0 else 0.0
        recall = round(float(tp / (tp + fn)), 4) if (tp + fn) > 0 else 0.0
        f1 = round(float(2 * precision * recall / (precision + recall)), 4) if (precision + recall) > 0 else 0.0
        fpr = round(float(fp / (fp + tn)), 4) if (fp + tn) > 0 else 0.0
        fnr = round(float(fn / (tp + fn)), 4) if (tp + fn) > 0 else 0.0
        
        per_class[cls_name] = {
            "support": support,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn
        }
    return per_class

def load_and_preprocess_dataset():
    """
    FR-01: Load and clean dataset (handle missing values, duplicates, infinite values).
    FR-02: Encode categorical features and scale numerical features.
    FR-03: Handle class imbalance using SMOTE on training set only (prevent leakage).
    Split: 70% train, 15% validation, 15% test (stratified 3-way split).
    """
    if not os.path.exists(DATA_PATH):
        from data_generator import generate_and_save_all_datasets
        generate_and_save_all_datasets()
        
    df = pd.read_csv(DATA_PATH)
    
    # Cleaning: Handle missing values, infinite values, drop duplicates to prevent leakage
    init_len = len(df)
    df = df.drop_duplicates()
    duplicates_removed = init_len - len(df)
    df = df.replace([np.inf, -np.inf], np.nan)
    
    for col in NUMERICAL_FEATURES:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
            df[col] = df[col].fillna(df[col].median())
            
    for col in CATEGORICAL_FEATURES:
        if col in df.columns:
            df[col] = df[col].fillna("unknown").astype(str)

    # Encode categoricals
    proto_map = {val: idx for idx, val in enumerate(df["proto"].unique())}
    service_map = {val: idx for idx, val in enumerate(df["service"].unique())}
    state_map = {val: idx for idx, val in enumerate(df["state"].unique())}
    
    df["proto_code"] = df["proto"].map(proto_map).fillna(0)
    df["service_code"] = df["service"].map(service_map).fillna(0)
    df["state_code"] = df["state"].map(state_map).fillna(0)
    
    encoded_feature_cols = NUMERICAL_FEATURES + ["proto_code", "service_code", "state_code"]
    
    # Encode target labels
    le = LabelEncoder()
    df["target"] = le.fit_transform(df["attack_cat"])
    
    X = df[encoded_feature_cols].copy()
    y = df["target"].copy()
    
    # 70% Train, 15% Val, 15% Test Stratified Split (Guaranteed Independent Test Set)
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    
    val_ratio_of_remaining = 0.15 / 0.85
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=val_ratio_of_remaining, random_state=42, stratify=y_train_val
    )
    
    original_train_count = len(X_train)
    val_count = len(X_val)
    test_count = len(X_test)
    
    # Feature Scaling: fit ONLY on training set to prevent data leakage
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=encoded_feature_cols)
    X_val_scaled = pd.DataFrame(scaler.transform(X_val), columns=encoded_feature_cols)
    X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=encoded_feature_cols)
    
    # Class Balancing with SMOTE on Training set only (FR-03)
    smote = SMOTE(random_state=42, k_neighbors=3)
    X_train_balanced, y_train_balanced = smote.fit_resample(X_train_scaled, y_train)
    
    # Post-SMOTE Categorical Constraint Enforcement:
    # Snap continuous interpolated values of categorical columns to their nearest valid discrete levels
    cat_cols_to_snap = ["proto_code", "service_code", "state_code"]
    for cat_col in cat_cols_to_snap:
        if cat_col in encoded_feature_cols:
            col_idx = encoded_feature_cols.index(cat_col)
            c_mean = scaler.mean_[col_idx]
            c_scale = scaler.scale_[col_idx]
            num_cats = len(df[cat_col.replace("_code", "")].unique())
            valid_discrete_scaled = np.array([(k - c_mean) / c_scale for k in range(num_cats)])
            col_vals = X_train_balanced[cat_col].values
            diffs = np.abs(col_vals[:, None] - valid_discrete_scaled[None, :])
            nearest_indices = diffs.argmin(axis=1)
            X_train_balanced[cat_col] = valid_discrete_scaled[nearest_indices]
    
    return {
        "X_train": X_train_balanced,
        "y_train": y_train_balanced,
        "X_val": X_val_scaled,
        "y_val": y_val,
        "X_test": X_test_scaled,
        "y_test": y_test,
        "original_train_count": original_train_count,
        "val_count": val_count,
        "test_count": test_count,
        "raw_df": df,
        "duplicates_removed": duplicates_removed,
        "feature_cols": encoded_feature_cols,
        "scaler": scaler,
        "label_encoder": le,
        "categorical_maps": {
            "proto": proto_map,
            "service": service_map,
            "state": state_map
        }
    }

def train_and_evaluate_all():
    """
    Trains Random Forest, XGBoost, and Isolation Forest.
    Evaluates all 3 models on the independent hold-out test set according to PRD Section 12 & FR-15.
    Calculates Accuracy, Precision, Recall, F1-Score, FPR, FNR, ROC-AUC (without fabricated fallbacks),
    prediction latency per flow, and granular per-class breakdown.
    """
    print("=" * 60)
    print("   AI Network Intrusion Detection: Pipeline Training")
    print("=" * 60)
    
    prep = load_and_preprocess_dataset()
    X_train = prep["X_train"]
    y_train = prep["y_train"]
    X_test = prep["X_test"]
    y_test = prep["y_test"]
    le = prep["label_encoder"]
    scaler = prep["scaler"]
    feature_cols = prep["feature_cols"]
    classes = list(le.classes_)
    
    normal_idx = list(classes).index("Normal") if "Normal" in classes else 0
    
    # -------------------------------------------------------------
    # Model 1: Random Forest Classifier (FR-04)
    # -------------------------------------------------------------
    print("\n[*] Training Random Forest Classifier...")
    rf_clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1
    )
    t0 = time.time()
    rf_clf.fit(X_train, y_train)
    rf_train_time = round(time.time() - t0, 3)
    
    # RF Test Prediction & Latency
    t0 = time.time()
    y_pred_rf = rf_clf.predict(X_test)
    rf_latency_per_flow = round(((time.time() - t0) / len(X_test)) * 1000, 3)
    y_prob_rf = rf_clf.predict_proba(X_test)
    
    rf_acc = accuracy_score(y_test, y_pred_rf)
    rf_prec_weighted = precision_score(y_test, y_pred_rf, average="weighted", zero_division=0)
    rf_prec_macro = precision_score(y_test, y_pred_rf, average="macro", zero_division=0)
    rf_rec_weighted = recall_score(y_test, y_pred_rf, average="weighted", zero_division=0)
    rf_rec_macro = recall_score(y_test, y_pred_rf, average="macro", zero_division=0)
    rf_f1_weighted = f1_score(y_test, y_pred_rf, average="weighted", zero_division=0)
    rf_f1_macro = f1_score(y_test, y_pred_rf, average="macro", zero_division=0)
    
    normal_mask = (y_test == normal_idx)
    rf_fpr = float(np.sum((normal_mask) & (y_pred_rf != normal_idx)) / np.sum(normal_mask))
    
    # Unbiased ROC-AUC calculation (No fabricated fallback)
    try:
        y_test_dummies = pd.get_dummies(y_test)
        rf_roc_auc = float(roc_auc_score(y_test_dummies, y_prob_rf, multi_class="ovr", average="weighted"))
        if np.isnan(rf_roc_auc):
            rf_roc_auc = None
        else:
            rf_roc_auc = round(rf_roc_auc, 4)
    except Exception as e:
        print(f"[!] Warning: ROC-AUC calculation failed for Random Forest ({e}). Reporting as unavailable.")
        rf_roc_auc = None
        
    rf_cm = confusion_matrix(y_test, y_pred_rf).tolist()
    rf_per_class = compute_per_class_metrics(y_test, y_pred_rf, classes)
    rf_brier = round(float(np.mean(np.sum((pd.get_dummies(y_test) - y_prob_rf)**2, axis=1))), 4)
    
    print(f"[OK] Random Forest - Accuracy: {rf_acc:.4f}, F1: {rf_f1_weighted:.4f}, FPR: {rf_fpr:.4f}, Latency: {rf_latency_per_flow} ms/flow")
    
    # -------------------------------------------------------------
    # Model 2: XGBoost Classifier (FR-04)
    # -------------------------------------------------------------
    print("\n[*] Training XGBoost Classifier...")
    xgb_clf = XGBClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        eval_metric="mlogloss",
        n_jobs=-1
    )
    t0 = time.time()
    xgb_clf.fit(X_train, y_train)
    xgb_train_time = round(time.time() - t0, 3)
    
    # XGB Test Prediction & Latency
    t0 = time.time()
    y_pred_xgb = xgb_clf.predict(X_test)
    xgb_latency_per_flow = round(((time.time() - t0) / len(X_test)) * 1000, 3)
    y_prob_xgb = xgb_clf.predict_proba(X_test)
    
    xgb_acc = accuracy_score(y_test, y_pred_xgb)
    xgb_prec_weighted = precision_score(y_test, y_pred_xgb, average="weighted", zero_division=0)
    xgb_prec_macro = precision_score(y_test, y_pred_xgb, average="macro", zero_division=0)
    xgb_rec_weighted = recall_score(y_test, y_pred_xgb, average="weighted", zero_division=0)
    xgb_rec_macro = recall_score(y_test, y_pred_xgb, average="macro", zero_division=0)
    xgb_f1_weighted = f1_score(y_test, y_pred_xgb, average="weighted", zero_division=0)
    xgb_f1_macro = f1_score(y_test, y_pred_xgb, average="macro", zero_division=0)
    
    xgb_fpr = float(np.sum((normal_mask) & (y_pred_xgb != normal_idx)) / np.sum(normal_mask))
    try:
        y_test_dummies = pd.get_dummies(y_test)
        xgb_roc_auc = float(roc_auc_score(y_test_dummies, y_prob_xgb, multi_class="ovr", average="weighted"))
        if np.isnan(xgb_roc_auc):
            xgb_roc_auc = None
        else:
            xgb_roc_auc = round(xgb_roc_auc, 4)
    except Exception as e:
        print(f"[!] Warning: ROC-AUC calculation failed for XGBoost ({e}). Reporting as unavailable.")
        xgb_roc_auc = None
        
    xgb_cm = confusion_matrix(y_test, y_pred_xgb).tolist()
    xgb_per_class = compute_per_class_metrics(y_test, y_pred_xgb, classes)
    xgb_brier = round(float(np.mean(np.sum((pd.get_dummies(y_test) - y_prob_xgb)**2, axis=1))), 4)
    
    print(f"[OK] XGBoost - Accuracy: {xgb_acc:.4f}, F1: {xgb_f1_weighted:.4f}, FPR: {xgb_fpr:.4f}, Latency: {xgb_latency_per_flow} ms/flow")
    
    # -------------------------------------------------------------
    # Model 3: Isolation Forest (FR-05 - Unsupervised Anomaly Detection)
    # -------------------------------------------------------------
    print("\n[*] Training Isolation Forest Anomaly Detector...")
    X_train_normal = X_train[y_train == normal_idx]
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.08,
        random_state=42,
        n_jobs=-1
    )
    t0 = time.time()
    iso_forest.fit(X_train_normal)
    iso_train_time = round(time.time() - t0, 3)
    
    t0 = time.time()
    iso_pred_raw = iso_forest.predict(X_test)
    iso_latency_per_flow = round(((time.time() - t0) / len(X_test)) * 1000, 3)
    
    binary_y_test = (y_test != normal_idx).astype(int)
    binary_iso_pred = (iso_pred_raw == -1).astype(int)
    
    iso_acc = accuracy_score(binary_y_test, binary_iso_pred)
    iso_prec = precision_score(binary_y_test, binary_iso_pred, zero_division=0)
    iso_rec = recall_score(binary_y_test, binary_iso_pred, zero_division=0)
    iso_f1 = f1_score(binary_y_test, binary_iso_pred, zero_division=0)
    iso_fpr = float(np.sum((binary_y_test == 0) & (binary_iso_pred == 1)) / np.sum(binary_y_test == 0))
    
    iso_scores = -iso_forest.decision_function(X_test)
    try:
        iso_roc_auc = float(roc_auc_score(binary_y_test, iso_scores))
        if np.isnan(iso_roc_auc):
            iso_roc_auc = None
        else:
            iso_roc_auc = round(iso_roc_auc, 4)
    except Exception as e:
        print(f"[!] Warning: ROC-AUC calculation failed for Isolation Forest ({e}). Reporting as unavailable.")
        iso_roc_auc = None
        
    print(f"[OK] Isolation Forest - Anomaly F1: {iso_f1:.4f}, FPR: {iso_fpr:.4f}, Latency: {iso_latency_per_flow} ms/flow")

    # -------------------------------------------------------------
    # SHAP Explainer Initialization (FR-12)
    # -------------------------------------------------------------
    print("\n[*] Pre-fitting SHAP TreeExplainer on Random Forest...")
    background_sample = X_train.sample(n=min(50, len(X_train)), random_state=42)
    shap_explainer = shap.TreeExplainer(rf_clf, data=background_sample)
    
    importances = rf_clf.feature_importances_
    feature_importance_list = [
        {"feature": feat, "importance": round(float(imp), 4)}
        for feat, imp in sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True)
    ]

    # -------------------------------------------------------------
    # Save Model Artifacts
    # -------------------------------------------------------------
    print("\n[*] Saving models and artifacts to disk...")
    joblib.dump(rf_clf, RF_MODEL_PATH)
    joblib.dump(xgb_clf, XGB_MODEL_PATH)
    joblib.dump(iso_forest, ISO_MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le, LABEL_ENCODER_PATH)
    joblib.dump(feature_cols, FEATURE_NAMES_PATH)
    joblib.dump(prep["categorical_maps"], os.path.join(MODELS_DIR, "categorical_maps.joblib"))
    joblib.dump(background_sample, os.path.join(MODELS_DIR, "shap_background.joblib"))

    # Model Comparison Summary (FR-15, Section 12)
    comparison_report = {
        "dataset": {
            "name": "Synthetic Network Intrusion Benchmark (modeled after UNSW-NB15 / CICIDS2017 distributions)",
            "data_type": "Synthetic / Simulated Benchmark",
            "benchmark_note": "Dataset is synthetically generated with statistical distributions modeled after UNSW-NB15 and CICIDS2017. High metric scores reflect performance on this synthetic evaluation set and do not establish guaranteed operational efficacy on heterogeneous real-world production networks.",
            "total_samples": len(prep["raw_df"]),
            "original_train_samples": prep["original_train_count"],
            "smote_resampled_train_samples": len(X_train),
            "validation_samples": prep["val_count"],
            "test_samples": len(X_test),
            "classes": classes,
            "features_count": len(feature_cols),
            "data_leakage_safeguards": {
                "split_strategy": "Stratified 3-way hold-out (70% Train, 15% Val, 15% Independent Test)",
                "scaler_fit": "Train split only (zero leakage)",
                "smote_applied": "Train split only (categorical levels snapped to discrete states)",
                "duplicates_removed": prep["duplicates_removed"]
            }
        },
        "target_f1_score": 0.90,
        "latency_threshold_ms": 100.0,
        "models": {
            "random_forest": {
                "name": "Random Forest Classifier",
                "type": "Supervised Ensemble (Bagging)",
                "accuracy": round(float(rf_acc), 4),
                "precision_weighted": round(float(rf_prec_weighted), 4),
                "recall_weighted": round(float(rf_rec_weighted), 4),
                "f1_score_weighted": round(float(rf_f1_weighted), 4),
                "precision_macro": round(float(rf_prec_macro), 4),
                "recall_macro": round(float(rf_rec_macro), 4),
                "f1_score_macro": round(float(rf_f1_macro), 4),
                "false_positive_rate": round(float(rf_fpr), 4),
                "roc_auc": round(float(rf_roc_auc), 4),
                "brier_score": rf_brier,
                "prediction_latency_ms": round(float(rf_latency_per_flow), 3),
                "train_time_sec": round(float(rf_train_time), 2),
                "confusion_matrix": rf_cm,
                "per_class_metrics": rf_per_class,
                "meets_f1_target": bool(rf_f1_weighted >= 0.90),
                "meets_latency_target": bool(rf_latency_per_flow < 100.0)
            },
            "xgboost": {
                "name": "XGBoost Classifier",
                "type": "Supervised Gradient Boosting",
                "accuracy": round(float(xgb_acc), 4),
                "precision_weighted": round(float(xgb_prec_weighted), 4),
                "recall_weighted": round(float(xgb_rec_weighted), 4),
                "f1_score_weighted": round(float(xgb_f1_weighted), 4),
                "precision_macro": round(float(xgb_prec_macro), 4),
                "recall_macro": round(float(xgb_rec_macro), 4),
                "f1_score_macro": round(float(xgb_f1_macro), 4),
                "false_positive_rate": round(float(xgb_fpr), 4),
                "roc_auc": round(float(xgb_roc_auc), 4),
                "brier_score": xgb_brier,
                "prediction_latency_ms": round(float(xgb_latency_per_flow), 3),
                "train_time_sec": round(float(xgb_train_time), 2),
                "confusion_matrix": xgb_cm,
                "per_class_metrics": xgb_per_class,
                "meets_f1_target": bool(xgb_f1_weighted >= 0.90),
                "meets_latency_target": bool(xgb_latency_per_flow < 100.0)
            },
            "isolation_forest": {
                "name": "Isolation Forest",
                "type": "Unsupervised Anomaly Detection",
                "accuracy": round(float(iso_acc), 4),
                "precision": round(float(iso_prec), 4),
                "recall": round(float(iso_rec), 4),
                "f1_score": round(float(iso_f1), 4),
                "false_positive_rate": round(float(iso_fpr), 4),
                "roc_auc": round(float(iso_roc_auc), 4),
                "prediction_latency_ms": round(float(iso_latency_per_flow), 3),
                "train_time_sec": round(float(iso_train_time), 2),
                "meets_latency_target": bool(iso_latency_per_flow < 100.0)
            }
        },
        "feature_importance": feature_importance_list[:10],
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    with open(METADATA_PATH, "w") as f:
        json.dump(comparison_report, f, indent=2)

    print(f"[+] Model comparison metrics written to {METADATA_PATH}")
    print("[OK] Model training and evaluation successfully completed!")
    return comparison_report

if __name__ == "__main__":
    train_and_evaluate_all()

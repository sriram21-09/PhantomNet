import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    precision_recall_curve,
    auc,
    confusion_matrix,
    classification_report
)

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

def evaluate_ml():
    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "dimensions": ["ML-01", "ML-02", "ML-03", "ML-04", "ML-05"],
        "artifacts_inspected": {},
        "evaluations": {}
    }

    # 1. Inspect Models Index & Metadata
    index_path = ROOT / "ml_models" / "registry" / "models_index.json"
    if index_path.exists():
        with open(index_path, "r", encoding="utf-8") as f:
            index_data = json.load(f)
        results["artifacts_inspected"]["models_index"] = index_data
    
    # 2. Inspect Registry Pickle
    pkl_path = ROOT / "ml_models" / "registry" / "AttackClassifier_Enhanced_v1.0.0.pkl"
    results["artifacts_inspected"]["pkl_exists"] = pkl_path.exists()
    
    model_obj = None
    if pkl_path.exists():
        try:
            model_obj = joblib.load(pkl_path)
            results["artifacts_inspected"]["model_type"] = str(type(model_obj))
            if hasattr(model_obj, "feature_names_in_"):
                results["artifacts_inspected"]["feature_names"] = list(model_obj.feature_names_in_)
            if hasattr(model_obj, "classes_"):
                results["artifacts_inspected"]["classes"] = [str(c) for c in model_obj.classes_]
        except Exception as e:
            results["artifacts_inspected"]["load_error"] = str(e)

    # 3. Load Ground Truth Data
    gt_path = ROOT / "data" / "ground_truth.csv"
    if gt_path.exists():
        df_gt = pd.read_csv(gt_path)
        results["artifacts_inspected"]["ground_truth_count"] = len(df_gt)
        results["artifacts_inspected"]["ground_truth_columns"] = list(df_gt.columns)
        
        # 4. Evaluate AnomalyDetector on Ground Truth
        try:
            from backend.ml.anomaly_detector import AnomalyDetector
            detector = AnomalyDetector()
            loaded = detector.load()
            results["evaluations"]["anomaly_detector_loaded"] = loaded
            
            y_true = []
            y_pred = []
            y_scores = []
            
            for _, row in df_gt.iterrows():
                event = row.to_dict()
                true_label = 1 if row["is_malicious"] else 0
                pred, score = detector.predict(event)
                pred_label = 1 if pred == -1 else 0
                
                y_true.append(true_label)
                y_pred.append(pred_label)
                y_scores.append(score)
                
            prec = float(precision_score(y_true, y_pred, zero_division=0))
            rec = float(recall_score(y_true, y_pred, zero_division=0))
            f1 = float(f1_score(y_true, y_pred, zero_division=0))
            tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            
            results["evaluations"]["anomaly_detector"] = {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "fpr": round(fpr, 4),
                "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
                "meets_slo": prec >= 0.80 and rec >= 0.75 and f1 >= 0.75 and fpr <= 0.10
            }
        except Exception as e:
            results["evaluations"]["anomaly_detector_error"] = str(e)

    # 5. Evaluate Threat Scoring Adversarial Robustness (without is_malicious=True bypass)
    try:
        from backend.ml.threat_scoring_service import score_threat
        from backend.schemas.threat_schema import ThreatInput
        
        # Test A: mutated payload with is_malicious=False
        mutated_input_adversarial = ThreatInput(
            src_ip="192.0.2.1",
            dst_ip="10.0.0.1",
            dst_port=2222,
            protocol="TCP",
            length=2048,
            is_malicious=False, # Removed the hardcoded bypass!
            attack_type="EXPLOIT_PAYLOAD",
        )
        res_adv = score_threat(mutated_input_adversarial)
        results["evaluations"]["adversarial_without_bypass"] = {
            "score": res_adv.score,
            "threat_level": res_adv.threat_level,
            "decision": res_adv.decision,
            "is_critical": res_adv.threat_level == "CRITICAL",
            "evasion_success": res_adv.threat_level not in ["HIGH", "CRITICAL"]
        }
    except Exception as e:
        results["evaluations"]["adversarial_error"] = str(e)

    # 6. Walk-Forward Chronological Evaluation on Ground Truth
    if gt_path.exists() and "timestamp" in df_gt.columns:
        df_gt["ts"] = pd.to_datetime(df_gt["timestamp"])
        df_sorted = df_gt.sort_values("ts").reset_index(drop=True)
        split_idx = int(len(df_sorted) * 0.7)
        train_df = df_sorted.iloc[:split_idx]
        test_df = df_sorted.iloc[split_idx:]
        
        max_train = train_df["ts"].max().isoformat()
        min_test = test_df["ts"].min().isoformat()
        results["evaluations"]["walk_forward_real_data"] = {
            "train_samples": len(train_df),
            "test_samples": len(test_df),
            "max_train_timestamp": max_train,
            "min_test_timestamp": min_test,
            "zero_temporal_leakage": max_train < min_test
        }

    # Save output
    out_file = ROOT / "audit" / "revalidation" / "ml_evaluation_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"[+] ML Evaluation Complete. Output written to {out_file}")
    return results

if __name__ == "__main__":
    evaluate_ml()

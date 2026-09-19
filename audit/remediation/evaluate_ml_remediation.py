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
    classification_report,
    roc_auc_score
)

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

def run_ml_evaluation():
    print("=" * 60)
    print("PHANTOMNET V3 — ML PIPELINE EMPIRICAL REVALIDATION")
    print("=" * 60)

    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "methodology": "Strict chronological train/val/test split with zero temporal leakage",
        "ground_truth_file": "data/ground_truth.csv",
        "models_evaluated": {},
        "chronological_split": {},
        "threat_scoring_evasion_test": {}
    }

    gt_path = ROOT / "data" / "ground_truth.csv"
    if not gt_path.exists():
        print(f"ERROR: {gt_path} does not exist!")
        return

    df = pd.read_csv(gt_path)
    print(f"Loaded {len(df)} records from {gt_path}")
    print(f"Columns: {list(df.columns)}")

    # Ensure timestamp column and sort chronologically
    if "timestamp" in df.columns:
        df["ts"] = pd.to_datetime(df["timestamp"])
    elif "created_at" in df.columns:
        df["ts"] = pd.to_datetime(df["created_at"])
    else:
        df["ts"] = pd.date_range(start="2026-01-01", periods=len(df), freq="1min")

    df_sorted = df.sort_values("ts").reset_index(drop=True)

    # Strict Chronological Split: 70% Train, 15% Validation, 15% Test
    n = len(df_sorted)
    train_end = int(n * 0.70)
    val_end = int(n * 0.85)

    train_df = df_sorted.iloc[:train_end]
    val_df = df_sorted.iloc[train_end:val_end]
    test_df = df_sorted.iloc[val_end:]

    results["chronological_split"] = {
        "total_records": n,
        "train_count": len(train_df),
        "val_count": len(val_df),
        "test_count": len(test_df),
        "train_range": [str(train_df["ts"].min()), str(train_df["ts"].max())],
        "val_range": [str(val_df["ts"].min()), str(val_df["ts"].max())],
        "test_range": [str(test_df["ts"].min()), str(test_df["ts"].max())],
        "zero_temporal_leakage": (train_df["ts"].max() <= val_df["ts"].min()) and (val_df["ts"].max() <= test_df["ts"].min())
    }
    print(f"Chronological Split: Train={len(train_df)}, Val={len(val_df)}, Test={len(test_df)}")
    print(f"Zero Temporal Leakage: {results['chronological_split']['zero_temporal_leakage']}")

    # 1. Evaluate AnomalyDetector
    print("\n--- 1. Evaluating AnomalyDetector on Test Set ---")
    try:
        from backend.ml.anomaly_detector import AnomalyDetector
        detector = AnomalyDetector()
        loaded = detector.load()
        print(f"AnomalyDetector load status: {loaded}")

        y_true_ad = []
        y_pred_ad = []
        scores_ad = []

        for _, row in test_df.iterrows():
            event = row.to_dict()
            t_label = 1 if row.get("is_malicious", False) else 0
            pred, score = detector.predict(event)
            p_label = 1 if pred == -1 else 0
            y_true_ad.append(t_label)
            y_pred_ad.append(p_label)
            scores_ad.append(score)

        cm_ad = confusion_matrix(y_true_ad, y_pred_ad)
        tn, fp, fn, tp = cm_ad.ravel() if cm_ad.size == 4 else (0, 0, 0, 0)
        prec_ad = float(precision_score(y_true_ad, y_pred_ad, zero_division=0))
        rec_ad = float(recall_score(y_true_ad, y_pred_ad, zero_division=0))
        f1_ad = float(f1_score(y_true_ad, y_pred_ad, zero_division=0))
        fpr_ad = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        # PR-AUC
        try:
            precisions, recalls, _ = precision_recall_curve(y_true_ad, scores_ad)
            pr_auc_ad = float(auc(recalls, precisions))
        except Exception:
            pr_auc_ad = 0.0

        results["models_evaluated"]["AnomalyDetector"] = {
            "test_sample_count": len(test_df),
            "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
            "precision": round(prec_ad, 4),
            "recall": round(rec_ad, 4),
            "f1_score": round(f1_ad, 4),
            "fpr": round(fpr_ad, 4),
            "pr_auc": round(pr_auc_ad, 4),
            "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
            "meets_slo": (prec_ad >= 0.80 and rec_ad >= 0.75 and f1_ad >= 0.75 and fpr_ad <= 0.10)
        }
        print(f"AnomalyDetector: Prec={prec_ad:.4f}, Rec={rec_ad:.4f}, F1={f1_ad:.4f}, FPR={fpr_ad:.4f}, PR-AUC={pr_auc_ad:.4f}")
        print(f"TP={tp}, TN={tn}, FP={fp}, FN={fn}")
    except Exception as e:
        print(f"Error evaluating AnomalyDetector: {e}")
        results["models_evaluated"]["AnomalyDetector_error"] = str(e)

    # 2. Evaluate AttackClassifier_Enhanced
    print("\n--- 2. Evaluating AttackClassifier_Enhanced on Test Set ---")
    classifier_path = ROOT / "ml_models" / "registry" / "AttackClassifier_Enhanced_v1.0.0.pkl"
    if classifier_path.exists():
        try:
            clf = joblib.load(classifier_path)
            print(f"Loaded classifier: {type(clf)}")
            
            # Extract features for test set using FeatureExtractor
            from backend.ml.threat_scoring_service import _FEATURE_EXTRACTOR, FeatureExtractor
            
            X_test_list = []
            y_test_list = []
            
            for _, row in test_df.iterrows():
                event = row.to_dict()
                feat = _FEATURE_EXTRACTOR.extract_features(event)
                X_test_list.append(feat)
                y_test_list.append(1 if row.get("is_malicious", False) else 0)

            X_test_df = pd.DataFrame(X_test_list, columns=FeatureExtractor.FEATURE_NAMES)
            
            # Align features if model expects fewer/different feature count
            if hasattr(clf, "n_features_in_") and isinstance(getattr(clf, "n_features_in_", None), int):
                n_feat = clf.n_features_in_
                feat_names = getattr(clf, "feature_names_in_", None)
                if feat_names is not None and hasattr(feat_names, "__iter__") and not isinstance(feat_names, (str, bytes)):
                    avail_cols = [c for c in feat_names if c in X_test_df.columns]
                    if len(avail_cols) == n_feat:
                        X_test_aligned = X_test_df[avail_cols]
                    else:
                        X_test_aligned = X_test_df.iloc[:, :n_feat].values
                else:
                    X_test_aligned = X_test_df.iloc[:, :n_feat].values
            else:
                X_test_aligned = X_test_df

            y_pred_clf = clf.predict(X_test_aligned)
            if hasattr(clf, "predict_proba"):
                y_proba_clf = clf.predict_proba(X_test_aligned)[:, 1]
            else:
                y_proba_clf = y_pred_clf

            cm_clf = confusion_matrix(y_test_list, y_pred_clf)
            tn_c, fp_c, fn_c, tp_c = cm_clf.ravel() if cm_clf.size == 4 else (0, 0, 0, 0)
            prec_c = float(precision_score(y_test_list, y_pred_clf, zero_division=0))
            rec_c = float(recall_score(y_test_list, y_pred_clf, zero_division=0))
            f1_c = float(f1_score(y_test_list, y_pred_clf, zero_division=0))
            fpr_c = float(fp_c / (fp_c + tn_c)) if (fp_c + tn_c) > 0 else 0.0

            try:
                precisions_c, recalls_c, _ = precision_recall_curve(y_test_list, y_proba_clf)
                pr_auc_c = float(auc(recalls_c, precisions_c))
            except Exception:
                pr_auc_c = 0.0

            try:
                roc_auc_c = float(roc_auc_score(y_test_list, y_proba_clf))
            except Exception:
                roc_auc_c = 0.0

            results["models_evaluated"]["AttackClassifier_Enhanced"] = {
                "test_sample_count": len(test_df),
                "tp": int(tp_c), "tn": int(tn_c), "fp": int(fp_c), "fn": int(fn_c),
                "precision": round(prec_c, 4),
                "recall": round(rec_c, 4),
                "f1_score": round(f1_c, 4),
                "fpr": round(fpr_c, 4),
                "pr_auc": round(pr_auc_c, 4),
                "roc_auc": round(roc_auc_c, 4),
                "confusion_matrix": [[int(tn_c), int(fp_c)], [int(fn_c), int(tp_c)]],
                "meets_slo": (prec_c >= 0.80 and rec_c >= 0.75 and f1_c >= 0.75 and fpr_c <= 0.10)
            }
            print(f"AttackClassifier_Enhanced: Prec={prec_c:.4f}, Rec={rec_c:.4f}, F1={f1_c:.4f}, FPR={fpr_c:.4f}, PR-AUC={pr_auc_c:.4f}, ROC-AUC={roc_auc_c:.4f}")
            print(f"TP={tp_c}, TN={tn_c}, FP={fp_c}, FN={fn_c}")

            # Update models_index.json with real empirical metrics
            index_path = ROOT / "ml_models" / "registry" / "models_index.json"
            if index_path.exists():
                with open(index_path, "r", encoding="utf-8") as f:
                    idx_data = json.load(f)
                if "models" in idx_data and "v1.0.0" in idx_data["models"]:
                    idx_data["models"]["v1.0.0"]["metrics"] = {
                        "accuracy": round(float((tp_c + tn_c) / len(y_test_list)), 4),
                        "precision": round(prec_c, 4),
                        "recall": round(rec_c, 4),
                        "f1_score": round(f1_c, 4),
                        "fpr": round(fpr_c, 4),
                        "pr_auc": round(pr_auc_c, 4),
                        "auc": round(roc_auc_c, 4),
                        "timestamp": datetime.utcnow().isoformat(),
                        "model_version": "v1.0.0",
                        "evaluation_dataset": "data/ground_truth.csv (strict chronological test split)",
                        "evaluation_samples": len(test_df)
                    }
                    with open(index_path, "w", encoding="utf-8") as f:
                        json.dump(idx_data, f, indent=4)
                    print(f"[OK] Updated models_index.json with empirical metrics.")

        except Exception as e:
            print(f"Error evaluating AttackClassifier_Enhanced: {e}")
            results["models_evaluated"]["AttackClassifier_error"] = str(e)
    else:
        print(f"Warning: {classifier_path} not found.")

    # 3. Evaluate Adversarial Robustness without bypass
    print("\n--- 3. Evaluating Adversarial Evasion (without is_malicious bypass) ---")
    try:
        from backend.ml.threat_scoring_service import score_threat
        from backend.schemas.threat_schema import ThreatInput

        test_payloads = [
            {
                "name": "mutated_exploit_payload",
                "input": ThreatInput(
                    src_ip="192.0.2.1",
                    dst_ip="10.0.0.1",
                    dst_port=2222,
                    protocol="TCP",
                    length=2048,
                    attack_type="EXPLOIT_PAYLOAD",
                )
            },
            {
                "name": "slow_ssh_brute_force",
                "input": ThreatInput(
                    src_ip="198.51.100.42",
                    dst_ip="10.0.0.1",
                    dst_port=22,
                    protocol="TCP",
                    length=88,
                    honeypot_type="SSH",
                    attack_type="SSH_BRUTE_FORCE",
                )
            },
            {
                "name": "distributed_sqli_botnet",
                "input": ThreatInput(
                    src_ip="203.0.113.50",
                    dst_ip="10.0.0.5",
                    dst_port=8080,
                    protocol="TCP",
                    length=350,
                    honeypot_type="HTTP",
                    attack_type="SQL_INJECTION",
                    threat_score=65.0,
                )
            }
        ]

        adv_results = []
        for p in test_payloads:
            res = score_threat(p["input"])
            adv_results.append({
                "payload_name": p["name"],
                "score": res.score,
                "threat_level": res.threat_level,
                "confidence": res.confidence,
                "decision": res.decision,
                "evaded": res.threat_level == "LOW" or res.decision == "ALLOW"
            })
            print(f"Payload '{p['name']}': Level={res.threat_level}, Decision={res.decision}, Score={res.score}")

        results["threat_scoring_evasion_test"] = adv_results
    except Exception as e:
        print(f"Error evaluating adversarial robustness: {e}")
        results["threat_scoring_evasion_test_error"] = str(e)

    # Save results
    out_file = ROOT / "audit" / "remediation" / "ml_revalidation_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved empirical ML evaluation results to {out_file}")

if __name__ == "__main__":
    run_ml_evaluation()

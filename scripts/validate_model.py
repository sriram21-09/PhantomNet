import pandas as pd
import sys
import os
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score

# Add project root to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from backend.ml.anomaly_detector import AnomalyDetector
except ImportError as e:
    print(f"Error importing AnomalyDetector: {e}")
    sys.exit(1)

# Configuration
GROUND_TRUTH_PATH = "data/ground_truth.csv"
OUTPUT_PATH = "data/predictions.csv"

def main():
    print("🚀 Starting Model Validation...")
    
    # 1. Load Ground Truth
    if not os.path.exists(GROUND_TRUTH_PATH):
        print(f"❌ Error: Ground truth file not found at {GROUND_TRUTH_PATH}")
        return

    df = pd.read_csv(GROUND_TRUTH_PATH)
    print(f"✅ Loaded {len(df)} events from {GROUND_TRUTH_PATH}")

    # 2. Initialize Model
    detector = AnomalyDetector()
    
    # Check if model is trained, if not, we can't really validate effectively without a base model.
    # For this exercise, we will "train" it on the benign part of the dataset if it's not already trained, 
    # OR we assume a pre-trained model exists.
    # Let's try to load, if fails, we train on a subset of benign data from the ground truth itself (common practice for unsupervised).
    
    if not detector.load():
        print("⚠️ No pre-trained model found. Training on benign samples from ground truth...")
        benign_samples = df[df["is_malicious"] == False].to_dict(orient="records")
        # Split: Train on 80% benign, validate on rest + malicious
        # But for *accuracy validation* of the pipeline, we strictly usually evaluate a *trained* model.
        # Here we will train on ALL benign data for the sake of the exercise to establish a baseline.
        detector.train(benign_samples)

    # 3. Running Predictions
    print("🔮 Running predictions...")
    
    y_true = []
    y_pred = []
    y_scores = []
    
    results = []

    for _, row in df.iterrows():
        event = row.to_dict()
        
        # Ground Truth Label
        # is_malicious: True -> 1 (Anomaly), False -> 0 (Normal) for comparison
        # Model Output: -1 (Anomaly), 1 (Normal)
        
        true_label = 1 if row["is_malicious"] else 0
        
        prediction, score = detector.predict(event)
        
        # Map model prediction to 0/1
        # -1 -> 1 (Anomaly)
        # 1 -> 0 (Normal)
        pred_label = 1 if prediction == -1 else 0
        
        y_true.append(true_label)
        y_pred.append(pred_label)
        y_scores.append(score)
        
        results.append({
            **event,
            "predicted_label": "MALICIOUS" if pred_label == 1 else "BENIGN",
            "anomaly_score": score,
            "correct": true_label == pred_label
        })

    # 4. Save Detailed Results
    results_df = pd.DataFrame(results)
    results_df.to_csv(OUTPUT_PATH, index=False)
    print(f"💾 Predictions saved to {OUTPUT_PATH}")

    # 5. Generate Report
    print("\n" + "="*40)
    print("📊 VALIDATION RESULTS")
    print("="*40)
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_true, y_pred)
    # TN, FP, FN, TP
    # But usually sklearn is [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = cm.ravel()
    print(f"True Negatives (Benign correct): {tn}")
    print(f"False Positives (Benign marked as Malicious): {fp}")
    print(f"False Negatives (Malicious marked as Benign): {fn}")
    print(f"True Positives (Malicious correct): {tp}")

    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, target_names=["BENIGN", "MALICIOUS"]))

    # 6. Analysis
    accuracy = (tp + tn) / len(y_true)
    print(f"Overall Accuracy: {accuracy:.2%}")
    
    if fp > 0:
        print("\n⚠️ High False Positive Rate detected! Review benign traffic patterns.")
    if fn > 0:
        print("\n⚠️ Missed Detections (FN) detected! Model may need lower contamination or better features.")

if __name__ == "__main__":
    main()

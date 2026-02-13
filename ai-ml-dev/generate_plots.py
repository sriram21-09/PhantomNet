import os
import sys
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_curve, auc, RocCurveDisplay, ConfusionMatrixDisplay

# Configure paths
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "model_performance")
dataset_path = os.path.join(DATA_DIR, "training_dataset.csv")
model_path = os.path.join(MODELS_DIR, "isolation_forest_optimized.pkl")
scaler_path = os.path.join(MODELS_DIR, "scaler_v1.pkl")

# Ensure reports directory exists
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_plots():
    print("🚀 Generating Model Performance Plots...")
    
    # 1. Load Data
    if not os.path.exists(dataset_path):
        print(f"❌ Error: Dataset not found at {dataset_path}")
        sys.exit(1)
    
    df = pd.read_csv(dataset_path)
    
    # 2. Preprocess (Same as training)
    feature_cols = [
        "packet_length", "protocol_encoding", "source_ip_event_rate",
        "destination_port_class", "threat_score", "malicious_flag_ratio",
        "attack_type_frequency", "time_of_day_deviation", "burst_rate",
        "packet_size_variance", "honeypot_interaction_count",
        "session_duration_estimate", "unique_destination_count",
        "rolling_average_deviation", "z_score_anomaly"
    ]
    
    X = df[feature_cols].copy()
    X.fillna(0, inplace=True)
    
    if 'label' in df.columns:
        y = df['label'].values
    else:
        print("❌ Error: Labels are required for plotting.")
        sys.exit(1)
        
    # 3. Load Model and Scaler
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
         print(f"❌ Error: Model or Scaler not found in {MODELS_DIR}")
         sys.exit(1)
         
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    
    X_scaled = scaler.transform(X)
    
    # 4. Predict
    # Isolation Forest: -1 for anomaly, 1 for normal
    y_pred_raw = model.predict(X_scaled)
    y_pred = np.where(y_pred_raw == -1, 1, 0)
    
    # Decision function: lower is more anomalous. 
    # For ROC, we need a score where higher = positive class (anomaly).
    # IF decision_function returns higher values for 'normal' observations.
    # So we negate it to get higher values for 'anomalies'.
    y_scores = -model.decision_function(X_scaled)
    
    # 5. Plot Confusion Matrix
    print("📊 Generating Confusion Matrix...")
    cm = confusion_matrix(y, y_pred)
    plt.figure(figsize=(8, 6))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Normal", "Anomaly"])
    disp.plot(cmap=plt.cm.Blues, values_format='d')
    plt.title("Confusion Matrix - Isolation Forest")
    plt.savefig(os.path.join(REPORTS_DIR, "confusion_matrix.png"))
    plt.close()
    print("✅ Saved confusion_matrix.png")
    
    # 6. Plot ROC Curve
    print("📈 Generating ROC Curve...")
    fpr, tpr, thresholds = roc_curve(y, y_scores)
    roc_auc = auc(fpr, tpr)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC)')
    plt.legend(loc="lower right")
    plt.savefig(os.path.join(REPORTS_DIR, "roc_curve.png"))
    plt.close()
    print("✅ Saved roc_curve.png")

if __name__ == "__main__":
    generate_plots()

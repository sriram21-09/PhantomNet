"""
Script to train Isolation Forest model on Week 6 dataset.
Includes data loading, preprocessing, training, evaluation, and artifact saving.
"""

import os
import sys
import json
from datetime import datetime
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)
from sklearn.preprocessing import StandardScaler

# Configure paths
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
DOCS_DIR = os.path.join(PROJECT_ROOT, "docs")
dataset_path = os.path.join(DATA_DIR, "training_dataset.csv")

# Create directories if they don't exist
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(DOCS_DIR, exist_ok=True)

def load_data(filepath):
    """Load dataset from CSV."""
    if not os.path.exists(filepath):
        print(f"❌ Error: Dataset not found at {filepath}")
        sys.exit(1)
    
    print(f"📂 Loading dataset from {filepath}...")
    df = pd.read_csv(filepath)
    print(f"✅ Loaded {len(df)} records.")
    return df

def preprocess_data(df):
    """
    Preprocess data for Isolation Forest.
    Returns:
        X_scaled: Scaled feature matrix
        y: Labels (if available)
        scaler: The fitted scaler object
    """
    # Features to use based on inspection of training_dataset.csv
    feature_cols = [
        "packet_length", "protocol_encoding", "source_ip_event_rate",
        "destination_port_class", "threat_score", "malicious_flag_ratio",
        "attack_type_frequency", "time_of_day_deviation", "burst_rate",
        "packet_size_variance", "honeypot_interaction_count",
        "session_duration_estimate", "unique_destination_count",
        "rolling_average_deviation", "z_score_anomaly"
    ]
    
    # Ensure all columns exist
    missing_cols = [col for col in feature_cols if col not in df.columns]
    if missing_cols:
        print(f"❌ Error: Missing feature columns: {missing_cols}")
        sys.exit(1)

    X = df[feature_cols].copy()
    
    # Handle missing values (simple imputation with 0 for now based on data inspection)
    X.fillna(0, inplace=True)
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Labels (0 = Normal, 1 = Anomaly/Attack)
    # Note: training_dataset.csv has a 'label' column? Let's check.
    if 'label' in df.columns:
        y = df['label'].values
    else:
        print("⚠️ Warning: 'label' column not found. Evaluation metrics will be skipped.")
        y = None
        
    return X_scaled, y, scaler, feature_cols

def train_model(X, contamination=0.1):
    """Train Isolation Forest model."""
    print(f"🧠 Training Isolation Forest (n_estimators=100, contamination={contamination})...")
    
    # Initialize Isolation Forest with default parameters as requested
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X)
    print("✅ Model trained successfully.")
    return model

def evaluate_model(model, X, y):
    """Evaluate model performance."""
    if y is None:
        return {}
        
    print("📊 Evaluating model performance...")
    
    # Start timer
    start_time = datetime.now()
    
    # Predict anomalies
    # Isolation Forest returns 1 for inliers (normal), -1 for outliers (anomalies)
    y_pred_raw = model.predict(X)
    
    # Convert predictions to 0 (normal) and 1 (anomaly) to match our labels
    y_pred = np.where(y_pred_raw == -1, 1, 0)
    
    # Calculate anomaly scores
    anomaly_scores = model.decision_function(X) # Higher is more normal, lower is more anomalous
    
    latency = (datetime.now() - start_time).total_seconds() * 1000
    
    # Metrics
    precision = precision_score(y, y_pred, zero_division=0)
    recall = recall_score(y, y_pred, zero_division=0)
    f1 = f1_score(y, y_pred, zero_division=0)
    try:
        roc_auc = roc_auc_score(y, -anomaly_scores) # Negate score because lower is more anomalous
    except ValueError:
        roc_auc = 0.0
        
    cm = confusion_matrix(y, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    metrics = {
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "roc_auc": float(roc_auc),
        "confusion_matrix": {
            "tn": int(tn), "fp": int(fp),
            "fn": int(fn), "tp": int(tp)
        },
        "latency_ms": latency
    }
    
    print(f"   Precision: {precision:.4f}")
    print(f"   Recall:    {recall:.4f}")
    print(f"   F1 Score:  {f1:.4f}")
    print(f"   ROC AUC:   {roc_auc:.4f}")
    
    return metrics

def save_artifacts(model, metrics, scaler, feature_cols, config):
    """Save model and metadata."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save Model
    model_path = os.path.join(MODELS_DIR, "isolation_forest_v1.pkl")
    joblib.dump(model, model_path)
    print(f"💾 Saved model to {model_path}")
    
    # Save Scaler (important for inference pipeline!)
    scaler_path = os.path.join(MODELS_DIR, "scaler_v1.pkl")
    joblib.dump(scaler, scaler_path)
    print(f"💾 Saved scaler to {scaler_path}")

    # Save Config
    config_path = os.path.join(MODELS_DIR, "training_config.json")
    with open(config_path, "w") as f:
        json.dump(config, f, indent=4)
    print(f"💾 Saved config to {config_path}")
    
    # Generate Stats Report
    stats_path = os.path.join(DOCS_DIR, "dataset_statistics.md")
    with open(stats_path, "w") as f:
        f.write(f"# Dataset Statistics Report\n")
        f.write(f"Generated: {timestamp}\n\n")
        f.write(f"## Training Configuration\n")
        f.write(f"- Model: Isolation Forest\n")
        f.write(f"- Dataset: {os.path.basename(dataset_path)}\n")
        f.write(f"- Features: {len(feature_cols)}\n")
        f.write(f"- Contamination: {config['contamination']}\n\n")
        
        if metrics:
            f.write(f"## Model Performance\n")
            f.write(f"- Precision: {metrics['precision']:.4f}\n")
            f.write(f"- Recall: {metrics['recall']:.4f}\n")
            f.write(f"- F1 Score: {metrics['f1_score']:.4f}\n")
            f.write(f"- ROC AUC: {metrics['roc_auc']:.4f}\n\n")
            f.write(f"### Confusion Matrix\n")
            f.write(f"| | Predicted Normal | Predicted Anomaly |\n")
            f.write(f"|---|---|---|\n")
            f.write(f"| **Actual Normal** | {metrics['confusion_matrix']['tn']} | {metrics['confusion_matrix']['fp']} |\n")
            f.write(f"| **Actual Anomaly** | {metrics['confusion_matrix']['fn']} | {metrics['confusion_matrix']['tp']} |\n")
    
    print(f"📄 Generated report at {stats_path}")

def main():
    print("🚀 Starting Isolation Forest Training Pipeline...")
    
    # 1. Load Data
    df = load_data(dataset_path)
    
    # 2. Preprocess
    X_scaled, y, scaler, feature_cols = preprocess_data(df)
    
    # 3. Parameter Configuration
    # Auto-adjust contamination based on label ratio if possible, else default
    default_contamination = 0.1
    if y is not None:
        anomaly_ratio = sum(y) / len(y)
        print(f"ℹ️  Dataset anomaly ratio: {anomaly_ratio:.4f}")
        # Use actual ratio or slightly higher for robustness? Usually IF is unsupervised.
        # Let's stick to default 0.1 unless ratio is vastly different to avoid overfitting?
        # Actually, if we know the labels, let's set contamination close to reality or 'auto'
        # For this exercise, let's use 'auto' or fixed 0.1 as per prompt requirement "default parameters"
        contamination = 0.1 
    else:
        contamination = default_contamination

    config = {
        "model_type": "IsolationForest",
        "n_estimators": 100,
        "contamination": contamination,
        "input_features": feature_cols,
        "random_state": 42
    }
    
    # 4. Train
    model = train_model(X_scaled, contamination=contamination)
    
    # 5. Evaluate
    metrics = evaluate_model(model, X_scaled, y)
    
    # 6. Save
    save_artifacts(model, metrics, scaler, feature_cols, config)
    
    print("\n✅ Training Pipeline Completed Successfully!")

if __name__ == "__main__":
    main()

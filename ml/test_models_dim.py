import pandas as pd
import joblib

print("Loading dataset...")
df = pd.read_csv("backend/ml/datasets/labeled_events_v2_enhanced.csv")
print(f"Dataset columns ({len(df.columns)}):", list(df.columns))

print("\nLoading RF...")
rf = joblib.load("ml/models/attack_classifier_v2_optimized.pkl")
print("RF Pipeline steps:", rf.steps)
# Number of expected features in pipeline
if hasattr(rf.named_steps['scaler'], 'n_features_in_'):
    print("RF expected features:", rf.named_steps['scaler'].n_features_in_)

print("\nLoading IF...")
if_model = joblib.load("models/isolation_forest_v1.pkl")
if hasattr(if_model, "n_features_in_"):
    print("IF expected features:", if_model.n_features_in_)

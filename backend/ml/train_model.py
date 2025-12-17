import pandas as pd
import pickle
import os
from sklearn.ensemble import RandomForestClassifier

# 1. Define the "Fake" Training Data
# (In real life, this comes from the database, but we need to bootstrap the AI)
data = [
    # [duration, event_count, unique_ports, events_per_sec, IS_THREAT?]
    [10, 50, 5, 5.0, 1],   # High speed, many ports -> THREAT (1)
    [2, 1, 1, 0.5, 0],     # Slow, single event -> SAFE (0)
    [300, 500, 20, 1.6, 1],# Sustained attack -> THREAT (1)
    [5, 2, 1, 0.4, 0],     # Normal user -> SAFE (0)
    [60, 100, 10, 1.6, 1]  # Medium attack -> THREAT (1)
]

# Convert to DataFrame
df = pd.DataFrame(data, columns=["duration", "event_count", "unique_ports", "eps", "label"])

# 2. Split Features (X) and Answer Key (y)
X = df[["duration", "event_count", "unique_ports", "eps"]]
y = df["label"]

# 3. Initialize the Brain (Random Forest)
print("🧠 Training Random Forest Model...")
model = RandomForestClassifier(n_estimators=10)
model.fit(X, y)

# 4. Save the "Brain" to a file (.pkl)
# We save it in the same folder as this script
current_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(current_dir, "threat_model.pkl")

with open(model_path, "wb") as f:
    pickle.dump(model, f)

print(f"✅ Model saved successfully at: {model_path}")
print("   (You can now load this file to predict threats!)")
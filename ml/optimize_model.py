import pandas as pd
import numpy as np
import joblib
import os
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.feature_selection import SelectFromModel
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score

def optimize():
    print("Optimization Process Started...")
    dataset_path = "backend/ml/datasets/labeled_events_v2_enhanced.csv"
    
    if not os.path.exists(dataset_path):
        print(f"Dataset not found at {dataset_path}")
        return

    df = pd.read_csv(dataset_path)
    X = df.drop("label", axis=1)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Pipeline: Scaler -> Feature Selection -> RF
    selector = SelectFromModel(RandomForestClassifier(n_estimators=50, random_state=42), threshold="median")
    rf = RandomForestClassifier(random_state=42, n_jobs=1)

    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('feature_selection', selector),
        ('classifier', rf)
    ])

    param_grid = {
        'classifier__n_estimators': [50, 100],
        'classifier__max_depth': [10, 15],
        'classifier__min_samples_split': [5, 10]
    }

    print("Running GridSearchCV for Hyperparameter Tuning & Tree Pruning...")
    start_time = time.time()
    grid_search = GridSearchCV(pipeline, param_grid, cv=3, scoring='accuracy', n_jobs=1, verbose=1)
    grid_search.fit(X_train, y_train)
    print(f"GridSearchCV completed in {time.time() - start_time:.2f} seconds.")

    best_model = grid_search.best_estimator_
    print(f"Best Parameters: {grid_search.best_params_}")

    curr_features = df.shape[1] - 1
    selected_features = best_model.named_steps['feature_selection'].get_support().sum()
    print(f"Features simplified from {curr_features} to {selected_features}")

    # Validation
    y_pred = best_model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Optimized Model Accuracy: {acc:.4f}")

    # Save
    out_dir = "ml/models"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "attack_classifier_v2_optimized.pkl")
    joblib.dump(best_model, out_path)
    print(f"Optimized model saved to {out_path}")

if __name__ == "__main__":
    optimize()

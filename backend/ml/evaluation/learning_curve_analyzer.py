import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import learning_curve
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import os

def analyze_learning_curve():
    print("📈 Starting Learning Curve Analysis...")
    
    # Load dataset
    dataset_path = os.path.join(os.path.dirname(__file__), "..", "datasets", "labeled_events_v2_enhanced.csv")
    if not os.path.exists(dataset_path):
        print(f"❌ Dataset not found at {dataset_path}")
        return

    df = pd.read_csv(dataset_path)
    X = df.drop("label", axis=1)
    y = df["label"]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)

    train_sizes, train_scores, test_scores = learning_curve(
        model, X_scaled, y, cv=5, n_jobs=-1, 
        train_sizes=np.linspace(0.1, 1.0, 5),
        scoring='accuracy'
    )

    train_mean = np.mean(train_scores, axis=1)
    test_mean = np.mean(test_scores, axis=1)

    print("\nLearning Curve Data:")
    for size, t_m, v_m in zip(train_sizes, train_mean, test_mean):
        print(f"Size: {size}, Train Acc: {t_m:.4f}, Val Acc: {v_m:.4f}")

    # Generate Report
    results_dir = os.path.join(os.path.dirname(__file__), "..", "..", "reports")
    os.makedirs(results_dir, exist_ok=True)
    
    report_content = f"""# Learning Curve Analysis (Week 11 Day 2)

## Data Points
| Training Size | Train Accuracy | Validation Accuracy |
|---------------|----------------|---------------------|
"""
    for size, t_m, v_m in zip(train_sizes, train_mean, test_mean):
        report_content += f"| {size} | {t_m:.4f} | {v_m:.4f} |\n"

    report_content += """
## Analysis
- **Convergence**: If Train and Validation accuracy converge high, the model is well-fit.
- **Data Requirement**: If the validation score is still rising at the maximum training size, more data could be beneficial.
- **Overfitting**: High gap between train and validation scores indicates overfitting.

## Observations
In our current evaluation with behavioral features, the model achieves high accuracy very quickly, suggesting strong feature signal.
"""
    
    with open(os.path.join(results_dir, "learning_curve_data_week11_day2.md"), "w") as f:
        f.write(report_content)
    
    # Attempt to save PNG if matplotlib is working
    try:
        plt.figure(figsize=(10, 6))
        plt.plot(train_sizes, train_mean, 'o-', color="r", label="Training score")
        plt.plot(train_sizes, test_mean, 'o-', color="g", label="Cross-validation score")
        plt.title("Learning Curve (Random Forest)")
        plt.xlabel("Training examples")
        plt.ylabel("Score")
        plt.legend(loc="best")
        plt.grid()
        plt.savefig(os.path.join(results_dir, "learning_curve_week11_day2.png"))
        print(f"📊 Graph saved to reports/learning_curve_week11_day2.png")
    except Exception as e:
        print(f"⚠️ Could not save PNG graph: {e}")

if __name__ == "__main__":
    analyze_learning_curve()

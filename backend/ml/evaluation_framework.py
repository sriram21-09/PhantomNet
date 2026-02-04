import pandas as pd


class ModelComparisonTable:
    def __init__(self):
        self.results = []

    def add_model_result(
        self,
        model_name,
        accuracy,
        precision,
        recall,
        f1,
        latency_ms
    ):
        self.results.append({
            "Model": model_name,
            "Accuracy": round(accuracy, 4),
            "Precision": round(precision, 4),
            "Recall": round(recall, 4),
            "F1-Score": round(f1, 4),
            "Avg Inference Latency (ms)": round(latency_ms, 2)
        })

    def to_dataframe(self):
        return pd.DataFrame(self.results)

    def display(self):
        df = self.to_dataframe()
        print("\n--- Model Comparison Table ---")
        print(df.to_string(index=False))
        return df

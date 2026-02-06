import pytest
import numpy as np
import pandas as pd
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from backend.ml.error_analysis import (
    compute_misclassification_indices,
    analyze_error_distribution,
    get_error_samples,
    generate_error_summary
)
from backend.ml.class_imbalance import (
    compute_class_distribution,
    compute_per_class_metrics,
    assess_imbalance_impact,
    generate_imbalance_report
)


class TestErrorAnalysis:
    
    @pytest.fixture
    def sample_data(self):
        """Create sample data for testing."""
        X = pd.DataFrame({"feature1": [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]})
        y_true = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
        y_pred = np.array([0, 0, 1, 0, 0, 1, 0, 1, 1, 1])  # 1 FP (idx 2), 1 FN (idx 6)
        y_proba = np.array([0.1, 0.2, 0.7, 0.3, 0.2, 0.9, 0.4, 0.85, 0.95, 0.88])
        return X, y_true, y_pred, y_proba

    def test_compute_misclassification_indices(self, sample_data):
        X, y_true, y_pred, y_proba = sample_data
        result = compute_misclassification_indices(y_true, y_pred)
        
        assert "fp_indices" in result
        assert "fn_indices" in result
        assert len(result["fp_indices"]) == 1  # Index 2
        assert len(result["fn_indices"]) == 1  # Index 6
        assert 2 in result["fp_indices"]
        assert 6 in result["fn_indices"]

    def test_analyze_error_distribution(self, sample_data):
        X, y_true, y_pred, y_proba = sample_data
        result = analyze_error_distribution(X, y_true, y_pred, y_proba)
        
        assert result["summary"]["total_samples"] == 10
        assert result["summary"]["total_errors"] == 2
        assert result["summary"]["false_positives"] == 1
        assert result["summary"]["false_negatives"] == 1

    def test_get_error_samples_fp(self, sample_data):
        X, y_true, y_pred, y_proba = sample_data
        fp_samples = get_error_samples(X, y_true, y_pred, error_type="fp")
        
        assert len(fp_samples) == 1
        assert "actual" in fp_samples.columns
        assert "predicted" in fp_samples.columns
        assert "error_type" in fp_samples.columns

    def test_get_error_samples_fn(self, sample_data):
        X, y_true, y_pred, y_proba = sample_data
        fn_samples = get_error_samples(X, y_true, y_pred, error_type="fn")
        
        assert len(fn_samples) == 1

    def test_generate_error_summary(self, sample_data):
        X, y_true, y_pred, y_proba = sample_data
        analysis = analyze_error_distribution(X, y_true, y_pred, y_proba)
        summary = generate_error_summary(analysis)
        
        assert "ERROR ANALYSIS SUMMARY" in summary
        assert "False Positives" in summary
        assert "False Negatives" in summary


class TestClassImbalance:
    
    @pytest.fixture
    def sample_labels(self):
        # 70% class 0, 30% class 1
        y = np.array([0]*70 + [1]*30)
        return y

    def test_compute_class_distribution(self, sample_labels):
        result = compute_class_distribution(sample_labels)
        
        assert result["total_samples"] == 100
        assert "benign" in result["classes"]
        assert "attack" in result["classes"]
        assert result["classes"]["benign"]["count"] == 70
        assert result["classes"]["attack"]["count"] == 30
        assert result["imbalance_ratio"] == pytest.approx(70/30, rel=0.01)

    def test_compute_per_class_metrics(self):
        y_true = np.array([0, 0, 0, 1, 1, 1])
        y_pred = np.array([0, 0, 1, 1, 1, 0])  # 1 FP, 1 FN
        
        result = compute_per_class_metrics(y_true, y_pred)
        
        assert "benign" in result
        assert "attack" in result
        assert "precision" in result["benign"]
        assert "recall" in result["attack"]

    def test_assess_imbalance_impact_low(self):
        # Balanced scenario
        distribution = {
            "imbalance_ratio": 1.2,
            "classes": {
                "benign": {"ratio": 0.45},
                "attack": {"ratio": 0.55}
            }
        }
        per_class = {
            "benign": {"precision": 0.9, "recall": 0.85, "f1": 0.87, "support": 45},
            "attack": {"precision": 0.88, "recall": 0.9, "f1": 0.89, "support": 55}
        }
        
        result = assess_imbalance_impact(distribution, per_class, accuracy=0.87)
        
        assert result["severity"] == "low"
        assert "NOT materially affecting" in result["verdict"]

    def test_assess_imbalance_impact_high(self):
        # Imbalanced scenario with poor attack recall
        distribution = {
            "imbalance_ratio": 5.0,
            "classes": {
                "benign": {"ratio": 0.83},
                "attack": {"ratio": 0.17}
            }
        }
        per_class = {
            "benign": {"precision": 0.9, "recall": 0.95, "f1": 0.92, "support": 83},
            "attack": {"precision": 0.5, "recall": 0.5, "f1": 0.5, "support": 17}
        }
        
        result = assess_imbalance_impact(distribution, per_class, accuracy=0.85)
        
        assert result["severity"] == "high"
        assert len(result["issues"]) > 0

    def test_generate_imbalance_report(self, sample_labels):
        distribution = compute_class_distribution(sample_labels)
        y_pred = np.array([0]*65 + [1]*5 + [1]*25 + [0]*5)
        per_class = compute_per_class_metrics(sample_labels, y_pred)
        assessment = assess_imbalance_impact(distribution, per_class, accuracy=0.9)
        
        report = generate_imbalance_report(distribution, per_class, assessment)
        
        assert "CLASS IMBALANCE ANALYSIS REPORT" in report
        assert "VERDICT" in report

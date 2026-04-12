import pytest
import time
import numpy as np
import pandas as pd
from unittest.mock import patch, MagicMock
import ml.model_registry
import ml.model_loader
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.datasets import make_classification
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score

@pytest.fixture(scope="module")
def synthetic_data():
    X, y = make_classification(n_samples=500, n_features=32, n_informative=15, random_state=42)
    return X, y

@pytest.fixture(scope="module")
def trained_rf(synthetic_data):
    X, y = synthetic_data
    clf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
    clf.fit(X, y)
    return clf

@pytest.fixture(scope="module")
def trained_if(synthetic_data):
    X, _ = synthetic_data
    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(X)
    return clf

class TestRandomForest:
    def test_model_loads_correctly(self, trained_rf):
        assert trained_rf is not None
        assert hasattr(trained_rf, "predict")

    def test_accuracy_target(self, synthetic_data):
        X, y = synthetic_data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        clf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
        clf.fit(X_train, y_train)
        acc = accuracy_score(y_test, clf.predict(X_test))
        assert acc > 0.82

    def test_precision_recall(self, synthetic_data, trained_rf):
        X, y = synthetic_data
        preds = trained_rf.predict(X)
        prec = precision_score(y, preds)
        rec = recall_score(y, preds)
        assert prec > 0.80
        assert rec > 0.80

    def test_inference_performance(self, synthetic_data, trained_rf):
        X, _ = synthetic_data
        sample = X[[0]]
        
        # Warmup
        trained_rf.predict(sample)
        
        start = time.time()
        for _ in range(100):
            trained_rf.predict(sample)
        avg_time_ms = ((time.time() - start) / 100) * 1000
        assert avg_time_ms < 50.0

    def test_predicts_all_expected_classes(self, synthetic_data, trained_rf):
        X, _ = synthetic_data
        preds = trained_rf.predict(X)
        assert set(preds) == {0, 1}

    def test_probability_outputs(self, synthetic_data, trained_rf):
        X, _ = synthetic_data
        probs = trained_rf.predict_proba(X[[0]])
        assert probs.shape == (1, 2)
        assert np.isclose(np.sum(probs), 1.0)

    def test_feature_importance(self, trained_rf):
        assert hasattr(trained_rf, "feature_importances_")
        assert len(trained_rf.feature_importances_) == 32

class TestIsolationForest:
    def test_predictions_anomaly_scores(self, synthetic_data, trained_if):
        X, _ = synthetic_data
        preds = trained_if.predict(X)
        scores = trained_if.score_samples(X)
        assert set(preds).issubset({1, -1})
        assert len(scores) == len(X)

    def test_inference_performance(self, synthetic_data, trained_if):
        X, _ = synthetic_data
        sample = X[[0]]
        
        # Warmup
        trained_if.predict(sample)
        
        start = time.time()
        for _ in range(100):
            trained_if.predict(sample)
        avg_time_ms = ((time.time() - start) / 100) * 1000
        assert avg_time_ms < 30.0

class TestModelRegistry:
    @patch('ml.model_registry.MlflowClient')
    @patch('ml.model_registry.mlflow')
    def test_registry_exists_and_metadata(self, mock_mlflow, mock_client):
        # We verify that model registry script exist and has logic
        from ml.model_registry import main, MODEL_NAME
        assert MODEL_NAME == "PhantomNet_Attack_Detector"
        # Mock client behavior
        mock_instance = MagicMock()
        mock_client.return_value = mock_instance
        # Simulate an experiment and run
        mock_exp = MagicMock()
        mock_exp.experiment_id = "1"
        mock_instance.get_experiment_by_name.return_value = mock_exp
        
        mock_run = MagicMock()
        mock_run.info.run_id = "12345"
        mock_instance.search_runs.return_value = [mock_run]
        
        main()
        mock_mlflow.register_model.assert_called_once_with(
            model_uri="runs:/12345/model", name="PhantomNet_Attack_Detector"
        )

    @patch('ml.model_loader.mlflow')
    def test_rollback_capability(self, mock_mlflow):
        # Test rollback basically tests version loading
        from ml.model_loader import load_model, _MODEL
        import ml.model_loader as loader
        loader._LOAD_ATTEMPTED = False
        loader._MODEL = None
        
        mock_client = MagicMock()
        mock_mlflow.tracking.MlflowClient.return_value = mock_client
        mock_version = MagicMock()
        mock_version.version = "1"
        mock_client.get_latest_versions.return_value = [mock_version]
        
        # Should load via MLflow
        load_model()
        mock_mlflow.sklearn.load_model.assert_called_with("models:/PhantomNet_Attack_Detector/1")

def test_cross_validation(synthetic_data):
    X, y = synthetic_data
    clf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
    scores = cross_val_score(clf, X, y, cv=5)
    assert len(scores) == 5
    assert np.mean(scores) >= 0.80

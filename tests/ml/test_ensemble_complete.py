import pytest
import time
import numpy as np
import pandas as pd
from unittest.mock import patch, MagicMock
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.datasets import make_classification
from sklearn.metrics import accuracy_score
from ml.models.ensemble_predictor import EnsemblePredictor
from ml.feature_extractor import FeatureExtractor
from ml.config.thresholds import RF_WEIGHT, IF_WEIGHT

@pytest.fixture(scope="module")
def synthetic_data():
    # Generate canonical 12D data matching FeatureExtractor contract
    X, y = make_classification(
        n_samples=1000,
        n_features=12,
        n_informative=8,
        n_redundant=2,
        random_state=42,
    )
    df_X = pd.DataFrame(X, columns=FeatureExtractor.FEATURE_NAMES)
    return df_X, y

@pytest.fixture(scope="module")
def dummy_models(synthetic_data):
    X, y = synthetic_data
    # Train 12D RF
    rf = RandomForestClassifier(n_estimators=20, max_depth=5, random_state=42)
    rf.fit(X, y)
    
    # Train 12D IF
    isolation = IsolationForest(contamination=0.1, random_state=42)
    isolation.fit(X)
    
    return rf, isolation

@pytest.fixture
def predictor(dummy_models):
    rf, if_model = dummy_models
    # We bypass loading from disk by mocking os.path.exists and joblib.load
    with patch("os.path.exists", return_value=True), patch("joblib.load") as mock_load:
        mock_load.side_effect = [rf, if_model]
        pred = EnsemblePredictor(rf_path="dummy_rf.pkl", if_path="dummy_if.pkl")
    return pred

def test_ensemble_initialization(predictor):
    assert predictor.rf_model is not None
    assert predictor.if_model is not None
    assert predictor.w_rf == RF_WEIGHT   # Canonical 0.85
    assert predictor.w_if == IF_WEIGHT   # Canonical 0.15

def test_ensemble_output_format(predictor):
    rf_feat = pd.DataFrame(np.random.rand(1, 12), columns=FeatureExtractor.FEATURE_NAMES)
    if_feat = pd.DataFrame(np.random.rand(1, 12), columns=FeatureExtractor.FEATURE_NAMES)
    res = predictor.predict(rf_feat, if_feat)
    
    assert "prediction" in res
    assert "ensemble_score" in res
    assert "rf_prob" in res
    assert "if_score" in res
    assert "raw_if_score" in res
    assert "threat_level" in res
    assert "decision" in res
    assert isinstance(res["prediction"], int)
    assert 0.0 <= res["ensemble_score"] <= 1.0

def test_threat_scores_and_confidence(predictor):
    rf_feat = pd.DataFrame(np.random.rand(10, 12), columns=FeatureExtractor.FEATURE_NAMES)
    if_feat = pd.DataFrame(np.random.rand(10, 12), columns=FeatureExtractor.FEATURE_NAMES)
    
    res = predictor.predict_batch(rf_feat, if_feat)
    
    for score in res["ensemble_score"]:
        assert 0.0 <= score <= 1.0
        threat_score = score * 100
        assert 0.0 <= threat_score <= 100.0

def test_ensemble_accuracy_improvement(predictor, synthetic_data):
    X, y = synthetic_data
    
    # Ensemble accuracy on canonical 12D synthetic data
    res = predictor.predict_batch(X, X)
    ens_preds = res["ensemble_prediction"].values
    ens_acc = accuracy_score(y, ens_preds)
    
    assert ens_acc >= 0.80, f"Ensemble accuracy {ens_acc} is below 0.80 target"

def test_ensemble_performance(predictor, synthetic_data):
    X, _ = synthetic_data
    rf_feat = X.iloc[[0]]
    if_feat = X.iloc[[0]]
    
    # Warmup
    predictor.predict(rf_feat, if_feat)
    
    start = time.time()
    for _ in range(50):
        predictor.predict(rf_feat, if_feat)
    avg_time_ms = ((time.time() - start) / 50) * 1000
    
    assert avg_time_ms < 80.0

def test_batch_prediction_functionality(predictor, synthetic_data):
    X, _ = synthetic_data
    df = X.iloc[:100]
    
    start = time.time()
    res_df = predictor.predict_batch(df, df)
    time_taken = time.time() - start
    
    assert len(res_df) == 100
    assert "ensemble_score" in res_df.columns
    assert time_taken < 2.0

def test_rf_and_if_contributions(predictor):
    # Verify both models contribute according to canonical 0.85/0.15 formula
    rf_feat = pd.DataFrame(np.random.rand(1, 12), columns=FeatureExtractor.FEATURE_NAMES)
    if_feat = pd.DataFrame(np.random.rand(1, 12), columns=FeatureExtractor.FEATURE_NAMES)
    res = predictor.predict(rf_feat, if_feat)
    
    expected_score = (0.85 * res["rf_prob"]) + (0.15 * res["if_score"])
    assert np.isclose(res["ensemble_score"], expected_score)

def test_obsolete_weight_rejection_and_override():
    # Passing obsolete 0.70 / 0.30 should be overridden to canonical 0.85 / 0.15
    pred = EnsemblePredictor(w_rf=0.70, w_if=0.30)
    assert pred.w_rf == 0.85
    assert pred.w_if == 0.15

def test_incompatible_model_fails_explicitly():
    # Incompatible feature dimension (e.g. 32D or 6D) must raise ValueError
    mock_bad_model = MagicMock()
    mock_bad_model.n_features_in_ = 32
    
    with pytest.raises(ValueError, match="Incompatible"):
        EnsemblePredictor(rf_model=mock_bad_model)

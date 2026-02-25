import pandas as pd
import logging
from schemas.threat_schema import ThreatInput, ThreatResponse
import ml.model_loader as model_loader
from ml.feature_extractor import FeatureExtractor

# Setup Logger
logger = logging.getLogger(__name__)

# Singleton Feature Extractor to maintain state (e.g. rolling windows)
# In a real distributed system, state should be in Redis/KeyDB.
# For now, in-memory is acceptable per specs.
_FEATURE_EXTRACTOR = FeatureExtractor()

def map_score_to_level(score: float) -> str:
    """
    Maps a threat score (0-100) to a categorical level.
    """
    if score >= 75:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"

def map_score_to_decision(score: float) -> str:
    """
    Maps a threat score to a decision action.
    """
    if score >= 80:
        return "BLOCK"
    elif score >= 50:
        return "ALERT"
    else:
        return "ALLOW"

def score_threat(input_data: ThreatInput) -> ThreatResponse:
    """
    Orchestrates the scoring process:
    1. Converts Pydantic input to raw event dict.
    2. Extracts features using stateful extractor.
    3. Loads model (cached).
    4. Predicts probability.
    5. Returns formatted response.
    """
    model = model_loader.load_model()
    
    if not model:
        # Reduced to debug to avoid terminal flood as requested
        logger.debug("Model not available for scoring. Using fallback values.")
        # Fallback response if model is missing
        return ThreatResponse(
            score=0.0,
            threat_level="LOW",
            confidence=0.0,
            decision="ALLOW"
        )
        
    # 1. Convert Input to Dict (Raw Event)
    event = input_data.model_dump()
    
    # 2. Extract Features
    # This updates internal state of _FEATURE_EXTRACTOR
    features_dict = _FEATURE_EXTRACTOR.extract_features(event)
    
    # Ensure correct column order matching FeatureExtractor.FEATURE_NAMES
    # Convert to DataFrame (sklearn models usually expect 2D array or DF)
    feature_vector = pd.DataFrame([features_dict], columns=FeatureExtractor.FEATURE_NAMES)
    
    # 3. Predict
    # predict_proba returns [prob_benign, prob_malicious]
    try:
        # Check for predict_proba (Standard Classifiers)
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(feature_vector)
            malicious_prob = probabilities[0][1]
            score = malicious_prob * 100.0
            confidence = max(probabilities[0])
            
        # Check for Isolation Forest / One-Class SVM (predict returns -1 for anomaly)
        elif hasattr(model, "predict"):
            # Use .values to strip feature names and avoid sklearn warning
            pred = model.predict(feature_vector.values)[0]
            # IsolationForest: -1 = Anomaly, 1 = Normal
            if pred == -1:
                score = 85.0  # High threat (generic for anomaly)
                confidence = 0.85 # Estimated confidence
            else:
                score = 10.0  # Low threat
                confidence = 0.90
        else:
            raise AttributeError("Model has neither predict_proba nor predict")
        
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        # Valid model but prediction failed? Return Safe default
        return ThreatResponse(
            score=0.0,
            threat_level="LOW",
            confidence=0.0,
            decision="ERROR"
        )

    # 4. Construct Response
    return ThreatResponse(
        score=round(score, 2),
        threat_level=map_score_to_level(score),
        confidence=round(confidence, 2), 
        decision=map_score_to_decision(score)
    )

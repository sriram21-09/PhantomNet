import pandas as pd
import logging
import hashlib
import json
import redis
from schemas.threat_schema import ThreatInput, ThreatResponse
import ml.model_loader as model_loader
from ml.feature_extractor import FeatureExtractor
from typing import List

# Setup Logger
logger = logging.getLogger(__name__)

# Singleton Feature Extractor to maintain state (e.g. rolling windows)
# In a real distributed system, state should be in Redis/KeyDB.
# For now, in-memory is acceptable per specs.
_FEATURE_EXTRACTOR = FeatureExtractor()

try:
    redis_client = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)
    redis_client.ping()
    REDIS_AVAILABLE = True
    logger.info("Connected to Redis for prediction caching.")
except redis.ConnectionError:
    REDIS_AVAILABLE = False
    logger.warning("Redis not available. Running without prediction cache.")

def map_score_to_level(score: float, context: ThreatInput = None) -> str:
    """
    Maps a threat score (0-100) to a categorical level, applying dynamic
    threshold adjustments based on context (time of day, interaction type, reputation).
    """
    # Baseline thresholds (from ROC optimization)
    # The actual exact numbers can vary by analysis, but these match recent results roughly
    # We use 40 for medium, 75 for high, 90 for critical by default
    low_max = 40.0
    medium_max = 75.0
    high_max = 90.0

    if context:
        # Check source reputation
        if context.is_malicious:
            return "CRITICAL"
            
        # Contextual adjustment: more sensitive at night (00:00 - 05:00 UTC)
        if context.timestamp:
            try:
                from dateutil import parser
                dt = parser.parse(context.timestamp)
                if 0 <= dt.hour <= 5:
                    medium_max -= 10
                    high_max -= 10
            except:
                pass
                
        # Contextual adjustment: High interaction honeypots imply high danger
        if context.honeypot_type and context.honeypot_type.upper() in ["SSH", "TELNET", "RDP"]:
            medium_max -= 15
            high_max -= 15

    # Enforce minimum lower bounds so we don't accidentally class everything critical
    medium_max = max(20.0, medium_max)
    high_max = max(50.0, high_max)

    if score > high_max:
        return "CRITICAL"
    elif score > medium_max:
        return "HIGH"
    elif score > low_max:
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
    """ """

    # Check Prediction Cache first
    if REDIS_AVAILABLE:
        # Generate a deterministic hash for the raw event
        event_str = json.dumps(
            input_data.model_dump(exclude={"timestamp"}), sort_keys=True
        )
        event_hash = "pred_cache:" + hashlib.md5(event_str.encode()).hexdigest()

        cached_result = redis_client.get(event_hash)
        if cached_result:
            try:
                data = json.loads(cached_result)
                return ThreatResponse(**data)
            except Exception as e:
                logger.debug(f"Cache parse error: {e}")

    model = model_loader.load_model()

    if not model:
        # Reduced to debug to avoid terminal flood as requested
        logger.debug("Model not available for scoring. Using fallback values.")
        # Fallback response if model is missing
        return ThreatResponse(
            score=0.0, threat_level="LOW", confidence=0.0, decision="ALLOW"
        )

    # 1. Convert Input to Dict (Raw Event)
    event = input_data.model_dump()

    # 2. Extract Features
    # This updates internal state of _FEATURE_EXTRACTOR
    features_dict = _FEATURE_EXTRACTOR.extract_features(event)

    # Ensure correct column order matching FeatureExtractor.FEATURE_NAMES
    # Convert to DataFrame (sklearn models usually expect 2D array or DF)
    feature_vector = pd.DataFrame(
        [features_dict], columns=FeatureExtractor.FEATURE_NAMES
    )

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
                confidence = 0.85  # Estimated confidence
            else:
                score = 10.0  # Low threat
                confidence = 0.90
        else:
            raise AttributeError("Model has neither predict_proba nor predict")

    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        # Valid model but prediction failed? Return Safe default
        return ThreatResponse(
            score=0.0, threat_level="LOW", confidence=0.0, decision="ERROR"
        )

    # 4. Construct Response
    response = ThreatResponse(
        score=round(score, 2),
        threat_level=map_score_to_level(score, input_data),
        confidence=round(confidence, 2), 
        decision=map_score_to_decision(score)
    )

    # 5. Populate Cache (1 hour TTL)
    if REDIS_AVAILABLE:
        try:
            redis_client.setex(event_hash, 3600, response.model_dump_json())  # 1h TTL
        except Exception as e:
            logger.debug(f"Failed to cache prediction: {e}")

    return response


def score_threat_batch(inputs: List[ThreatInput]) -> List[ThreatResponse]:
    """
    Scores a batch of threats using vectorized operations where possible,
    drastically reducing model inference overhead compared to loops.
    """
    if not inputs:
        return []

    responses = [None] * len(inputs)
    uncached_indices = []
    uncached_events = []

    # 1. Check Cache
    hashes = []
    if REDIS_AVAILABLE:
        for i, inp in enumerate(inputs):
            event_str = json.dumps(
                inp.model_dump(exclude={"timestamp"}), sort_keys=True
            )
            hashes.append("pred_cache:" + hashlib.md5(event_str.encode()).hexdigest())

        try:
            cached_results = redis_client.mget(hashes)
            for i, result in enumerate(cached_results):
                if result:
                    responses[i] = ThreatResponse(**json.loads(result))
                else:
                    uncached_indices.append(i)
                    uncached_events.append(inputs[i].model_dump())
        except Exception as e:
            logger.warning(f"Batch cache read failed: {e}")
            uncached_indices = list(range(len(inputs)))
            uncached_events = [inp.model_dump() for inp in inputs]
    else:
        uncached_indices = list(range(len(inputs)))
        uncached_events = [inp.model_dump() for inp in inputs]

    if not uncached_indices:
        return responses

    # 2. Extract Features (Batch)
    model = model_loader.load_model()
    if not model:
        default_resp = ThreatResponse(
            score=0.0, threat_level="LOW", confidence=0.0, decision="ALLOW"
        )
        for i in uncached_indices:
            responses[i] = default_resp
        return responses

    features_list = [_FEATURE_EXTRACTOR.extract_features(ev) for ev in uncached_events]
    feature_matrix = pd.DataFrame(features_list, columns=FeatureExtractor.FEATURE_NAMES)

    # 3. Predict Batch
    try:
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(feature_matrix)
            malicious_probs = [p[1] for p in probabilities]
            confidences = [max(p) for p in probabilities]
            scores = [p * 100.0 for p in malicious_probs]

        elif hasattr(model, "predict"):
            preds = model.predict(feature_matrix.values)
            scores = [85.0 if p == -1 else 10.0 for p in preds]
            confidences = [0.85 if p == -1 else 0.90 for p in preds]
        else:
            raise AttributeError("Model has neither predict_proba nor predict")

    except Exception as e:
        logger.error(f"Batch prediction failed: {e}")
        default_resp = ThreatResponse(
            score=0.0, threat_level="LOW", confidence=0.0, decision="ERROR"
        )
        for i in uncached_indices:
            responses[i] = default_resp
        return responses

    # 4. Construct Responses and Cache
    cache_inserts = {}
    for idx, i in enumerate(uncached_indices):
        score = scores[idx]
        resp = ThreatResponse(
            score=round(score, 2),
            threat_level=map_score_to_level(score, inputs[i]),
            confidence=round(confidences[idx], 2),
            decision=map_score_to_decision(score),
        )
        responses[i] = resp
        if REDIS_AVAILABLE:
            cache_inserts[hashes[i]] = resp.model_dump_json()

    if REDIS_AVAILABLE and cache_inserts:
        try:
            # Atomic multi-set, rely on single TTL loop setting since redis MSET doesn't take TTL easily
            # We use a pipeline for TTL
            pipe = redis_client.pipeline()
            for key, val in cache_inserts.items():
                pipe.setex(key, 3600, val)
            pipe.execute()
        except Exception as e:
            logger.debug(f"Failed to multi-cache predictions: {e}")

    return responses

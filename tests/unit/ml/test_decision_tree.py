import pytest
import sys
import os

# Ensure backend can be imported if running this test file directly or via discovery
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from backend.ml.decision_tree import ResponseDecisionTree
from backend.ml.response_mapping import RESPONSE_MAP

class TestResponseDecisionTree:
    
    @pytest.fixture
    def decision_tree(self):
        return ResponseDecisionTree()

    def test_benign_traffic_log(self, decision_tree):
        """Test standard benign traffic results in LOG."""
        result = decision_tree.decide(
            prediction=0, 
            confidence=0.1, 
            anomaly_score=0.1, 
            threat_score=0.0
        )
        assert result == "LOG"

    def test_benign_traffic_high_anomaly(self, decision_tree):
        """Test benign prediction but high anomaly defaults to LOG (standard safety)."""
        result = decision_tree.decide(
            prediction=0, 
            confidence=0.1, 
            anomaly_score=0.9, 
            threat_score=0.0
        )
        assert result == "LOG"

    def test_attack_low_confidence_throttle(self, decision_tree):
        """Test attack with low confidence results in THROTTLE."""
        # Medium confidence is 0.6, so 0.5 should be low
        result = decision_tree.decide(
            prediction=1, 
            confidence=0.5, 
            anomaly_score=0.1, 
            threat_score=0.0
        )
        assert result == "THROTTLE"

    def test_attack_high_severity_block(self, decision_tree):
        """Test high confidence, anomaly, and threat results in BLOCK."""
        result = decision_tree.decide(
            prediction=1, 
            confidence=0.9, 
            anomaly_score=0.9, 
            threat_score=0.9
        )
        assert result == "BLOCK"

    def test_attack_medium_severity_deceive(self, decision_tree):
        """Test medium confidence and anomaly results in DECEIVE."""
        result = decision_tree.decide(
            prediction=1, 
            confidence=0.7, 
            anomaly_score=0.6, 
            threat_score=0.0
        )
        assert result == "DECEIVE"

    def test_attack_fallback_throttle(self, decision_tree):
        """Test attack matching no specific severe criteria falls back to THROTTLE."""
        # prediction=1, Conf=High, but Anomaly=Low. Should not Block or Deceive.
        result = decision_tree.decide(
            prediction=1, 
            confidence=0.9, 
            anomaly_score=0.1, 
            threat_score=0.0
        )
        assert result == "THROTTLE"

    def test_custom_thresholds_initialization(self):
        """Test that custom thresholds can be passed during initialization."""
        custom_thresholds = {"MEDIUM_CONFIDENCE": 0.9}
        dt = ResponseDecisionTree(thresholds=custom_thresholds)
        
        # With default (0.6), 0.7 would be >= Medium.
        # With custom (0.9), 0.7 is < Medium -> Should match Low Confidence logic (THROTTLE)
        # Assuming other params don't trigger higher severity
        
        result = dt.decide(
            prediction=1, 
            confidence=0.7, 
            anomaly_score=0.0, 
            threat_score=0.0
        )
        assert result == "THROTTLE" 

    def test_all_outputs_have_mapping(self, decision_tree):
        """Verify that every possible return value exists in RESPONSE_MAP."""
        possible_outputs = ["LOG", "THROTTLE", "DECEIVE", "BLOCK"]
        for output in possible_outputs:
            assert output in RESPONSE_MAP
            assert "action" in RESPONSE_MAP[output]
            assert "priority" in RESPONSE_MAP[output]

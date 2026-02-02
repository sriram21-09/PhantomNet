import React, { useEffect, useState } from "react";
import "./ThreatIndicator.css";
import { getEventFeatures } from "../api/mlClient";
import { normalSSHEvent } from "../mocks/mlMockData";

const ThreatIndicator = ({ eventId, threatScore: propThreatScore }) => {
  const [threatScore, setThreatScore] = useState(
    propThreatScore ??
      normalSSHEvent.features.threat_score.value ??
      0
  );
  const [_loading, setLoading] = useState(false);
  const [_error, setError] = useState(null);

  useEffect(() => {
    if (!eventId) return;

    const fetchThreatScore = async () => {
      setLoading(true);
      try {
        const response = await getEventFeatures(eventId);

        // ✅ Backend-ready + mock-safe
        if (response?.features?.threat_score?.value !== undefined) {
          setThreatScore(response.features.threat_score.value);
        }
      } catch (err) {
        console.warn("ThreatIndicator API failed, using mock score");
        setThreatScore(
          propThreatScore ??
            normalSSHEvent.features.threat_score.value ??
            0
        );
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchThreatScore();
  }, [eventId, propThreatScore]);

  // 🔹 Internal debug usage
  useEffect(() => {
    if (_loading) {
      console.debug("ThreatIndicator: loading threat score...");
    }
    if (_error) {
      console.debug("ThreatIndicator error:", _error);
    }
  }, [_loading, _error]);

  /* ======================
     UI BELOW — UNCHANGED
     ====================== */

  const getThreatLevel = () => {
    if (threatScore >= 80) return "High";
    if (threatScore >= 50) return "Medium";
    return "Low";
  };

  return (
    <div className="threat-indicator">
      <h3>Threat Level</h3>

      <div className="threat-bar-container">
        <div
          className={`threat-bar ${getThreatLevel().toLowerCase()}`}
          style={{ width: `${threatScore}%` }}
        ></div>
      </div>

      <p className="threat-score">
        {getThreatLevel()} ({threatScore}%)
      </p>
    </div>
  );
};

export default ThreatIndicator;

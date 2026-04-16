import { useContext, useState, useEffect } from "react";
import FeatureVector from "../components/FeatureVector";
import ThreatIndicator from "../components/ThreatIndicator";
import {
  normalSSHEvent,
  anomalousSSHEvent,
} from "../mocks/mlMockData";
import { ThemeContext } from "../context/ThemeContext";
import { FaBrain, FaCheck, FaExclamationTriangle, FaSatelliteDish, FaSpinner } from "react-icons/fa";
import "../Styles/pages/FeatureAnalysis.css";

const FeatureAnalysis = () => {
  const { theme } = useContext(ThemeContext);
  const [mode, setMode] = useState("live"); // 'live', 'normal', 'anomalous'
  const [liveEvent, setLiveEvent] = useState(null);
  const [isFetching, setIsFetching] = useState(false);

  useEffect(() => {
    let interval;
    if (mode === "live") {
      fetchLiveFeatures();
      interval = setInterval(fetchLiveFeatures, 3000); // 3 sec live polling
    }
    return () => clearInterval(interval);
  }, [mode]);

  const fetchLiveFeatures = async () => {
    setIsFetching(true);
    try {
      // Pull absolute latest event from db/cache
      const res = await fetch("/api/features/live");
      if (res.ok) {
        const data = await res.json();
        if (data.features && Object.keys(data.features).length > 0) {
           setLiveEvent(data);
        }
      }
    } catch (err) {
      console.error("Failed to fetch live features:", err);
    } finally {
      setIsFetching(false);
    }
  };

  const getActiveEvent = () => {
    if (mode === "live") return liveEvent || normalSSHEvent;
    if (mode === "normal") return normalSSHEvent;
    return anomalousSSHEvent;
  };

  const activeEvent = getActiveEvent();

  return (
    <div className="feature-wrapper">
      {/* Header */}
      <div className="feature-header">
        <div className="header-content">
          <div className="header-icon">
            <FaBrain />
          </div>
          <div>
            <h1>Feature Analysis</h1>
            <p>ML Feature Extraction • Threat Scoring Logic</p>
          </div>
        </div>
      </div>

      {/* Test Control Panel */}
      <div className="test-panel">
        <div className="panel-header">
          <h3>Test Controls</h3>
          <p>Switch between mock events to validate feature extraction and threat scoring logic.</p>
        </div>
        <div className="test-buttons" style={{flexWrap: 'wrap', gap: '10px'}}>
          <button
            className={`test-btn normal ${mode === "live" ? "active" : ""}`}
            style={{background: mode === "live" ? '#2563eb' : '', color: '#fff'}}
            onClick={() => setMode("live")}
          >
            <FaSatelliteDish className={isFetching ? "pulse" : ""} />
            Live Traffic Data
          </button>
          <button
            className={`test-btn normal ${mode === "normal" ? "active" : ""}`}
            onClick={() => setMode("normal")}
          >
            <FaCheck />
            Normal Event
          </button>
          <button
            className={`test-btn anomalous ${mode === "anomalous" ? "active" : ""}`}
            onClick={() => setMode("anomalous")}
          >
            <FaExclamationTriangle />
            Anomalous Event
          </button>
        </div>
      </div>

      {/* Feature Vector */}
      <div className="analysis-section">
        <FeatureVector
          eventId={activeEvent.eventId}
          featureVector={activeEvent}
        />
      </div>

      {/* Threat Indicator */}
      <div className="analysis-section">
        <ThreatIndicator
          eventId={activeEvent.eventId}
          threatScore={activeEvent.features?.threat_score?.value || 0}
        />
      </div>
    </div>
  );
};

export default FeatureAnalysis;

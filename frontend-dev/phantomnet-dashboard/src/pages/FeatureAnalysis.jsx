import { useContext, useState } from "react";
import FeatureVector from "../components/FeatureVector";
import ThreatIndicator from "../components/ThreatIndicator";
import {
  normalSSHEvent,
  anomalousSSHEvent,
} from "../mocks/mlMockData";
import { ThemeContext } from "../context/ThemeContext";
import { FaBrain, FaCheck, FaExclamationTriangle } from "react-icons/fa";
import "../styles/pages/FeatureAnalysis.css";

const FeatureAnalysis = () => {
  const { theme } = useContext(ThemeContext);
  const [testEvent, setTestEvent] = useState(normalSSHEvent);

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
        <div className="test-buttons">
          <button
            className={`test-btn normal ${testEvent === normalSSHEvent ? "active" : ""}`}
            onClick={() => setTestEvent(normalSSHEvent)}
          >
            <FaCheck />
            Normal Event
          </button>
          <button
            className={`test-btn anomalous ${testEvent === anomalousSSHEvent ? "active" : ""}`}
            onClick={() => setTestEvent(anomalousSSHEvent)}
          >
            <FaExclamationTriangle />
            Anomalous Event
          </button>
        </div>
      </div>

      {/* Feature Vector */}
      <div className="analysis-section">
        <FeatureVector
          eventId={testEvent.eventId}
          featureVector={testEvent}
        />
      </div>

      {/* Threat Indicator */}
      <div className="analysis-section">
        <ThreatIndicator
          eventId={testEvent.eventId}
          threatScore={testEvent.features.threat_score.value}
        />
      </div>
    </div>
  );
};

export default FeatureAnalysis;

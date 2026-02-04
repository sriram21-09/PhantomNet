import { useContext, useState } from "react";
import FeatureVector from "../components/FeatureVector";
import ThreatIndicator from "../components/ThreatIndicator";
import {
  normalSSHEvent,
  anomalousSSHEvent,
} from "../mocks/mlMockData";
import { ThemeContext } from "../context/ThemeContext";
import "./FeatureAnalysis.css";

const FeatureAnalysis = () => {
  const { theme } = useContext(ThemeContext);

  // 🔹 TEST-ONLY STATE
  const [testEvent, setTestEvent] = useState(normalSSHEvent);

  return (
    <div className={`page-container feature-analysis ${theme}`}>
      {/* =========================
          HEADER
      ========================== */}
      <div className="feature-header">
        <h1>Feature Analysis</h1>
        <p className="muted-text">
          Inspect extracted machine-learning features and
          analyze threat scores for security events.
        </p>
      </div>

      {/* =========================
          TEST CONTROL PANEL
      ========================== */}
      <div className="feature-test-panel">
        <h3>Test Controls</h3>
        <p className="muted-text">
          Switch between mock events to validate feature extraction
          and threat scoring logic.
        </p>

        <div className="test-buttons">
          <button
            className="secondary-btn"
            onClick={() => setTestEvent(normalSSHEvent)}
          >
            Normal Event
          </button>

          <button
            className="secondary-btn"
            onClick={() => setTestEvent(anomalousSSHEvent)}
          >
            Anomalous Event
          </button>
        </div>
      </div>

      {/* =========================
          FEATURE VECTOR
      ========================== */}
      <div className="feature-section">
        <FeatureVector
          eventId={testEvent.eventId}
          featureVector={testEvent}
        />
      </div>

      {/* =========================
          THREAT INDICATOR
      ========================== */}
      <div className="feature-section">
        <ThreatIndicator
          eventId={testEvent.eventId}
          threatScore={testEvent.features.threat_score.value}
        />
      </div>
    </div>
  );
};

export default FeatureAnalysis;

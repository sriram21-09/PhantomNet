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

  // 🔹 TEST-ONLY STATE (store full event)
  const [testEvent, setTestEvent] = useState(normalSSHEvent);

  return (
    <div className={`feature-analysis ${theme}`}>
      <h1>Feature Analysis Dashboard</h1>

      {/* =========================
          TEST CONTROL PANEL (DAY 5)
         ========================= */}
      <div
        style={{
          marginBottom: "24px",
          padding: "16px",
          borderRadius: "8px",
          border: "1px solid var(--border-color)",
          backgroundColor: "var(--card-bg)",
        }}
      >
        <h3 style={{ marginBottom: "8px" }}>Test Controls (Day 5)</h3>
        <p className="muted-text" style={{ marginBottom: "12px" }}>
          Switch between mock events to test FeatureVector and ThreatIndicator.
        </p>

        <button
          className="secondary-btn"
          style={{ marginRight: "12px" }}
          onClick={() => setTestEvent(normalSSHEvent)}
        >
          Load Normal Event (Low Threat)
        </button>

        <button
          className="secondary-btn"
          onClick={() => setTestEvent(anomalousSSHEvent)}
        >
          Load Anomalous Event (High Threat)
        </button>
      </div>

      {/* =========================
          FEATURE VECTOR
         ========================= */}
      <FeatureVector
        eventId={testEvent.eventId}
        featureVector={testEvent}  
      />

      {/* =========================
          THREAT INDICATOR
         ========================= */}
      <div style={{ marginTop: "24px" }}>
        <ThreatIndicator
          eventId={testEvent.eventId}
          threatScore={testEvent.features.threat_score.value}
        />
      </div>
    </div>
  );
};

export default FeatureAnalysis;

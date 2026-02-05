/**
 * Anomaly Dashboard
 * -----------------
 * High-level anomaly overview for SOC analysts.
 * Displays anomaly summary, severity breakdown,
 * and recent anomaly alerts.
 */

import { Link } from "react-router-dom";
import "../styles/anomaly-dashboard.css";
import AnomalyAlerts from "../components/AnomalyAlerts";

const AnomalyDashboard = () => {
  /**
   * Mock summary data
   * (API-ready – replace later with real backend call)
   */
  const summary = {
    totalAnomalies: 24,
    highSeverity: 6,
    mediumSeverity: 12,
    avgAnomalyScore: 68,
  };

  return (
    <div className="page-container anomaly-dashboard">
      {/* =========================
          HEADER
      ========================== */}
      <div className="anomaly-header">
        <h1>Anomaly Dashboard</h1>
        <p>
          Monitor unusual behavior, anomaly scores, and potential
          security threats detected across the network.
        </p>
      </div>

      {/* =========================
          SUMMARY METRICS
      ========================== */}
      <div className="anomaly-summary">
        <div className="anomaly-summary-card">
          <span className="label">Total Anomalies</span>
          <span className="value">{summary.totalAnomalies}</span>
        </div>

        <div className="anomaly-summary-card severity-high">
          <span className="label">High Severity</span>
          <span className="value">{summary.highSeverity}</span>
        </div>

        <div className="anomaly-summary-card severity-medium">
          <span className="label">Medium Severity</span>
          <span className="value">{summary.mediumSeverity}</span>
        </div>

        <div className="anomaly-summary-card">
          <span className="label">Avg Anomaly Score</span>

          {/* Progress bar */}
          <div className="score-bar">
            <div
              className="score-fill"
              style={{ width: `${summary.avgAnomalyScore}%` }}
            />
          </div>

          <span className="score-value">
            {summary.avgAnomalyScore}%
          </span>
        </div>
      </div>

      {/* =========================
          ALERTS SECTION
      ========================== */}
      <div className="anomaly-section">
        <div className="section-header">
          <h2>Recent Anomaly Alerts</h2>

          <Link to="/threat-analysis">
            <button className="secondary-btn">
              Go to Threat Analysis
            </button>
          </Link>
        </div>

        <AnomalyAlerts />
      </div>
    </div>
  );
};

export default AnomalyDashboard;

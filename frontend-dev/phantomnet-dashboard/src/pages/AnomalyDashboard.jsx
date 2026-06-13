/**
 * Anomaly Dashboard
 * -----------------
 * High-level anomaly overview for SOC analysts.
 * Displays anomaly summary, severity breakdown,
 * and recent anomaly alerts.
 */

import { Link } from "react-router-dom";
import "../Styles/anomaly-dashboard.css";
import AnomalyAlerts from "../components/AnomalyAlerts";

import React, { useState, useEffect } from "react";

const AnomalyDashboard = () => {
  const [summary, setSummary] = useState({
    totalAnomalies: 0,
    highSeverity: 0,
    mediumSeverity: 0,
    avgAnomalyScore: 0,
  });

  const fetchSummary = async () => {
    try {
      const res = await fetch('/api/v1/alerts?limit=100');
      if (res.ok) {
        const data = await res.json();
        const alertsList = data.alerts || [];
        
        const total = data.total || 0;
        const high = alertsList.filter(a => a.level === 'HIGH' || a.level === 'CRITICAL').length;
        const medium = alertsList.filter(a => a.level === 'MEDIUM').length;
        
        let scoreSum = 0;
        alertsList.forEach(a => {
          const l = a.level.toUpperCase();
          if (l === 'CRITICAL') scoreSum += 92;
          else if (l === 'HIGH') scoreSum += 78;
          else if (l === 'MEDIUM') scoreSum += 55;
          else scoreSum += 35;
        });
        const avgScore = alertsList.length > 0 ? Math.round(scoreSum / alertsList.length) : 0;

        setSummary({
          totalAnomalies: total,
          highSeverity: high,
          mediumSeverity: medium,
          avgAnomalyScore: avgScore
        });
      }
    } catch (err) {
      console.error("Failed to fetch anomaly summary:", err);
    }
  };

  useEffect(() => {
    fetchSummary();
    const interval = setInterval(fetchSummary, 5000);
    return () => clearInterval(interval);
  }, []);

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

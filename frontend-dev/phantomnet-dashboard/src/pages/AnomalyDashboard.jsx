import { Link } from "react-router-dom";
import "../Styles/anomaly-dashboard.css";
import AnomalyAlerts from "../components/AnomalyAlerts";
import React, { useState, useEffect } from "react";
import {
  FaListAlt,
  FaExclamationCircle,
  FaExclamationTriangle,
  FaChartLine,
  FaArrowRight
} from "react-icons/fa";

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
    <div className="page-container anomaly-dashboard-wrapper">
      {/* =========================
          HEADER
      ========================== */}
      <div className="anomaly-header">
        <div className="anomaly-badge hud-font">SECURITY_MONITOR_V1.2</div>
        <h1 className="anomaly-title">Anomaly Dashboard</h1>
        <p className="anomaly-subtitle">
          MONITOR UNUSUAL BEHAVIOR, ANOMALY SCORES, AND POTENTIAL NETWORK THREATS
        </p>
      </div>

      {/* =========================
          SUMMARY METRICS
      ========================== */}
      <div className="anomaly-summary-grid">
        {/* Total Anomalies */}
        <div className="anomaly-card card-total">
          <div className="hud-corner top-left"></div>
          <div className="hud-corner bottom-right"></div>
          <div className="card-top">
            <span className="card-subtitle">METRIC_01</span>
            <div className="icon-wrap">
              <FaListAlt />
            </div>
          </div>
          <div className="card-info">
            <span className="label">Total Anomalies</span>
            <span className="value">{summary.totalAnomalies}</span>
          </div>
          <div className="card-bar">
            <div className="card-bar-fill" style={{ width: summary.totalAnomalies > 0 ? '100%' : '0%' }}></div>
          </div>
          <div className="card-glow"></div>
        </div>

        {/* High Severity */}
        <div className="anomaly-card card-high">
          <div className="hud-corner top-left"></div>
          <div className="hud-corner bottom-right"></div>
          <div className="card-top">
            <span className="card-subtitle">CRITICAL_THREATS</span>
            <div className="icon-wrap">
              <FaExclamationCircle />
            </div>
          </div>
          <div className="card-info">
            <span className="label">High Severity</span>
            <span className="value">{summary.highSeverity}</span>
          </div>
          <div className="card-bar">
            <div className="card-bar-fill" style={{ width: summary.highSeverity > 0 ? '100%' : '0%' }}></div>
          </div>
          <div className="card-glow"></div>
        </div>

        {/* Medium Severity */}
        <div className="anomaly-card card-medium">
          <div className="hud-corner top-left"></div>
          <div className="hud-corner bottom-right"></div>
          <div className="card-top">
            <span className="card-subtitle">WARNINGS</span>
            <div className="icon-wrap">
              <FaExclamationTriangle />
            </div>
          </div>
          <div className="card-info">
            <span className="label">Medium Severity</span>
            <span className="value">{summary.mediumSeverity}</span>
          </div>
          <div className="card-bar">
            <div className="card-bar-fill" style={{ width: summary.mediumSeverity > 0 ? '100%' : '0%' }}></div>
          </div>
          <div className="card-glow"></div>
        </div>

        {/* Avg Anomaly Score */}
        <div className="anomaly-card card-avg">
          <div className="hud-corner top-left"></div>
          <div className="hud-corner bottom-right"></div>
          <div className="card-top">
            <span className="card-subtitle">ANALYTICS_SCORE</span>
            <div className="icon-wrap">
              <FaChartLine />
            </div>
          </div>
          <div className="card-info">
            <span className="label">Avg Anomaly Score</span>
            <div className="score-bar">
              <div
                className="score-fill"
                style={{ width: `${summary.avgAnomalyScore}%` }}
              />
            </div>
            <span className="score-value">{summary.avgAnomalyScore}%</span>
          </div>
          <div className="card-glow"></div>
        </div>
      </div>

      {/* =========================
          ALERTS SECTION
      ========================== */}
      <div className="anomaly-section">
        <div className="anomaly-section-header">
          <div className="section-title-group">
            <h2 className="section-title">Recent Anomaly Alerts</h2>
            <span className="section-count hud-font">REAL-TIME INTRUSION FEED</span>
          </div>

          <Link to="/threat-analysis" style={{ textDecoration: 'none' }}>
            <button className="go-btn hud-font">
              Go to Threat Analysis
              <FaArrowRight className="btn-arrow" />
            </button>
          </Link>
        </div>

        <AnomalyAlerts />
      </div>
    </div>
  );
};

export default AnomalyDashboard;

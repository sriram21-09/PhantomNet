import React, { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import "../Styles/anomaly-dashboard.css";
import AnomalyAlerts from "../components/AnomalyAlerts";
import { useRealTime } from "../context/RealTimeContext";
import { fetchAnomalyStats } from "../services/api";
import {
  FaListAlt,
  FaExclamationCircle,
  FaExclamationTriangle,
  FaChartLine,
  FaArrowRight,
  FaSyncAlt,
  FaShieldAlt,
} from "react-icons/fa";

const AnomalyDashboard = () => {
  const [dataMode, setDataMode] = useState("all"); // 'all' | 'live' | 'test'
  const [summary, setSummary] = useState({
    totalEvents: 0,
    totalAnomalies: 0,
    highSeverity: 0,
    mediumSeverity: 0,
    avgAnomalyScore: 0,
  });
  const [recentAnomalies, setRecentAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // WebSocket real-time integration
  const realTime = useRealTime();
  const wsMetrics = realTime?.metrics;
  const wsConnected = realTime?.isConnected;

  // Fetch telemetry from backend
  const fetchSummary = useCallback(async (isInitial = false) => {
    try {
      if (isInitial) setLoading(true);
      const data = await fetchAnomalyStats(dataMode);

      setSummary({
        totalEvents: data.totalEvents || 0,
        totalAnomalies: data.totalAnomalies !== undefined ? data.totalAnomalies : 0,
        highSeverity: data.highSeverity !== undefined ? data.highSeverity : 0,
        mediumSeverity: data.mediumSeverity !== undefined ? data.mediumSeverity : 0,
        avgAnomalyScore: data.avgAnomalyScore !== undefined ? data.avgAnomalyScore : 0,
      });
      setRecentAnomalies(data.recentAnomalies || []);
      setError(null);
    } catch (err) {
      setError(err.message || "Failed to load anomaly telemetry.");
    } finally {
      if (isInitial) setLoading(false);
    }
  }, [dataMode]);

  // Merge live WebSocket metrics when in 'all' or 'live' mode
  useEffect(() => {
    if (wsMetrics && dataMode !== "test") {
      setSummary((prev) => ({
        ...prev,
        totalEvents: wsMetrics.totalEvents ?? wsMetrics.total_events ?? prev.totalEvents,
        totalAnomalies: wsMetrics.totalAnomalies ?? prev.totalAnomalies,
        highSeverity: wsMetrics.highSeverity ?? prev.highSeverity,
        mediumSeverity: wsMetrics.mediumSeverity ?? prev.mediumSeverity,
        avgAnomalyScore: wsMetrics.avgAnomalyScore ?? prev.avgAnomalyScore,
      }));
      if (wsMetrics.recentAnomalies && wsMetrics.recentAnomalies.length > 0) {
        setRecentAnomalies(wsMetrics.recentAnomalies);
      }
    }
  }, [wsMetrics, dataMode]);

  // Initial load and periodic polling sync
  useEffect(() => {
    fetchSummary(true);
    const pollInterval = wsConnected ? 20000 : 8000;
    const interval = setInterval(() => fetchSummary(false), pollInterval);
    return () => clearInterval(interval);
  }, [fetchSummary, wsConnected]);

  // Proportional bar calculations
  const highRatio = summary.totalAnomalies > 0
    ? Math.min(100, Math.round((summary.highSeverity / summary.totalAnomalies) * 100))
    : 0;
  const medRatio = summary.totalAnomalies > 0
    ? Math.min(100, Math.round((summary.mediumSeverity / summary.totalAnomalies) * 100))
    : 0;
  const anomalyRatio = summary.totalEvents > 0
    ? Math.min(100, Math.round((summary.totalAnomalies / summary.totalEvents) * 100))
    : (summary.totalAnomalies > 0 ? 100 : 0);

  return (
    <div className="page-container anomaly-dashboard-wrapper">
      {/* =========================
          HEADER & DATASET SCOPE
      ========================== */}
      <div className="anomaly-header">
        <div className="anomaly-header-top">
          <div>
            <div className="anomaly-badge hud-font">
              <FaShieldAlt style={{ marginRight: "6px" }} />
              PHANTOMNET MACHINE LEARNING RADAR
            </div>
            <h1 className="anomaly-title">Anomaly Dashboard</h1>
            <p className="anomaly-subtitle">
              MONITOR UNUSUAL BEHAVIOR, ISOLATION FOREST SCORES, AND NETWORK INTRUSIONS
            </p>
          </div>

          {/* Dataset Scope Selector */}
          <div className="data-mode-container">
            <span className="mode-label hud-font">DATASET SCOPE:</span>
            <div className="data-mode-pills">
              <button
                type="button"
                className={`data-mode-btn ${dataMode === "all" ? "active" : ""}`}
                onClick={() => setDataMode("all")}
                title="Complete dataset: mixed live honeypot telemetry and baseline benchmarks"
              >
                All Events (Mixed)
              </button>
              <button
                type="button"
                className={`data-mode-btn live ${dataMode === "live" ? "active" : ""}`}
                onClick={() => setDataMode("live")}
                title="Strictly verified honeypot sensor telemetry (SSH, HTTP, FTP, SMTP)"
              >
                <span className="live-indicator-dot" /> Live Honeypots Only
              </button>
              <button
                type="button"
                className={`data-mode-btn ${dataMode === "test" ? "active" : ""}`}
                onClick={() => setDataMode("test")}
                title="Synthetic benchmark TCP dataset (RFC 5737 / stress testing)"
              >
                Test / Benchmark
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Telemetry Scope Disclosure Bar */}
      <div className="telemetry-disclosure-bar">
        <span className="disclosure-badge hud-font">
          {dataMode === "live" ? "VERIFIED SENSORS" : dataMode === "test" ? "SYNTHETIC BENCHMARK" : "MIXED TELEMETRY"}
        </span>
        <span className="disclosure-text">
          {dataMode === "live"
            ? "Showing 100% verified honeypot sensor telemetry (SSH, HTTP, FTP, SMTP) processed by Isolation Forest model."
            : dataMode === "test"
            ? "Showing baseline TCP benchmark dataset (RFC 5737 / stress evaluation) with unsupervised anomaly evaluation."
            : "Displaying unified telemetry from live honeypot sensors (SSH, HTTP, FTP, SMTP) and benchmark traffic."}
        </span>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="anomaly-error-banner">
          <div className="error-content">
            <FaExclamationCircle className="error-icon" />
            <span>{error}</span>
          </div>
          <button className="error-retry-btn hud-font" onClick={() => fetchSummary(true)}>
            <FaSyncAlt /> Retry
          </button>
        </div>
      )}

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
            <span className="value">
              {loading && summary.totalAnomalies === 0 ? "..." : summary.totalAnomalies.toLocaleString()}
            </span>
          </div>
          <div className="card-bar">
            <div className="card-bar-fill" style={{ width: `${anomalyRatio}%` }}></div>
          </div>
          <div className="card-footer-caption hud-font">
            {summary.totalEvents > 0 ? `${anomalyRatio}% of total traffic` : "Awaiting telemetry"}
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
            <span className="value">
              {loading && summary.highSeverity === 0 ? "..." : summary.highSeverity.toLocaleString()}
            </span>
          </div>
          <div className="card-bar">
            <div className="card-bar-fill" style={{ width: `${highRatio}%` }}></div>
          </div>
          <div className="card-footer-caption hud-font">
            {summary.totalAnomalies > 0 ? `${highRatio}% of anomalies (score ≥ 70%)` : "Score ≥ 70%"}
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
            <span className="value">
              {loading && summary.mediumSeverity === 0 ? "..." : summary.mediumSeverity.toLocaleString()}
            </span>
          </div>
          <div className="card-bar">
            <div className="card-bar-fill" style={{ width: `${medRatio}%` }}></div>
          </div>
          <div className="card-footer-caption hud-font">
            {summary.totalAnomalies > 0 ? `${medRatio}% of anomalies (40–69%)` : "Score 40–69%"}
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
                style={{ width: `${Math.min(100, summary.avgAnomalyScore)}%` }}
              />
            </div>
            <span className="score-value">
              {loading && summary.avgAnomalyScore === 0 ? "..." : `${summary.avgAnomalyScore}%`}
            </span>
          </div>
          <div className="card-footer-caption hud-font">
            ISOLATION FOREST BASELINE
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
            <h2 className="section-title">Recent Anomaly Events</h2>
            <span className="section-count hud-font">REAL-TIME INTRUSION FEED</span>
          </div>

          <Link to="/threat-analysis" style={{ textDecoration: 'none' }}>
            <button className="go-btn hud-font" type="button">
              Go to Threat Analysis
              <FaArrowRight className="btn-arrow" />
            </button>
          </Link>
        </div>

        <AnomalyAlerts
          recentAnomalies={recentAnomalies}
          loading={loading}
          error={error}
          onRetry={() => fetchSummary(true)}
        />
      </div>
    </div>
  );
};

export default AnomalyDashboard;

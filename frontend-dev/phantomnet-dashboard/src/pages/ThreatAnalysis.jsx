import { useState, useEffect, useCallback, useRef } from "react";
import { Link } from "react-router-dom";
import {
  FaExclamationTriangle,
  FaShieldAlt,
  FaSkull,
  FaCheckCircle,
  FaSyncAlt,
  FaSignInAlt,
} from "react-icons/fa";
import { useRealTime } from "../context/RealTimeContext";
import {
  fetchThreatSummary,
  fetchRecentThreatIndicators,
  fetchThreatAlerts,
} from "../services/api";
import "../Styles/pages/ThreatAnalysis.css";

const ALERT_ICONS = {
  critical: FaSkull,
  high: FaSkull,
  medium: FaExclamationTriangle,
  low: FaCheckCircle,
};

const ThreatAnalysis = () => {
  const { events: realtimeEvents, isConnected } = useRealTime();

  const [summary, setSummary] = useState({ active: 0, high: 0, medium: 0, low: 0, total: 0 });
  const [recentThreats, setRecentThreats] = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const prevRealtimeIdRef = useRef(null);
  const isFetchingRef = useRef(false);

  const loadData = useCallback(async (isInitial = false) => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;
    if (isInitial) setLoading(true);

    try {
      const [summaryRes, indicatorsRes, alertsRes] = await Promise.all([
        fetchThreatSummary("all"),
        fetchRecentThreatIndicators(8, "all"),
        fetchThreatAlerts(6, "all"),
      ]);

      // Authoritative summary metrics directly from database-level aggregation
      setSummary({
        active: summaryRes.activeThreats ?? 0,
        high: summaryRes.highSeverity ?? 0,
        medium: summaryRes.mediumSeverity ?? 0,
        low: summaryRes.lowSeverity ?? 0,
        total: summaryRes.totalEvents ?? 0,
      });

      // Format table indicators from authoritative backend response
      const indicators = (indicatorsRes || []).map((e) => ({
        id: e.id,
        time: e.time || "--:--",
        ip: e.ip || "Unknown",
        type: e.attack_type || e.type || "BENIGN",
        attack_type: e.attack_type || "BENIGN",
        score: Math.round(e.score !== undefined ? e.score : (e.threat_score ? e.threat_score * 100 : 0)),
        severity: e.severity || (e.threat_level ? e.threat_level.charAt(0).toUpperCase() + e.threat_level.slice(1).toLowerCase() : "Low"),
        decision: e.decision || "ALLOW",
      }));
      setRecentThreats(indicators);

      // Format live alerts from authoritative backend alerts (only genuine threats)
      const formattedAlerts = (alertsRes || []).map((a) => {
        const sev = (a.severity || "high").toLowerCase();
        return {
          id: a.id,
          severity: sev === "critical" ? "high" : sev,
          icon: ALERT_ICONS[sev] || ALERT_ICONS.high,
          message: a.message || `${(a.threat_level || "ALERT").toUpperCase()}: ${a.attack_type || "Threat"} from ${a.source_ip || "unknown"}`,
        };
      });
      setLiveAlerts(formattedAlerts);

      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      console.error("[ThreatAnalysis] Data load failed:", err);
      if (err.message && err.message.includes("AUTH_ERROR")) {
        setError({
          type: "auth",
          message: "Authentication required to view threat telemetry. Your session may have expired.",
        });
      } else {
        setError({
          type: "api",
          message: err.message || "Failed to load authoritative threat telemetry from server.",
        });
      }
    } finally {
      setLoading(false);
      isFetchingRef.current = false;
    }
  }, []);

  // Initial data load on mount
  useEffect(() => {
    loadData(true);
  }, [loadData]);

  // Real-time WebSocket event ingestion from singleton RealTimeContext
  useEffect(() => {
    if (!realtimeEvents || realtimeEvents.length === 0) return;

    const latest = realtimeEvents[0];
    if (!latest || latest.id === prevRealtimeIdRef.current) return;
    prevRealtimeIdRef.current = latest.id;

    // Check if event is a genuine threat (CRITICAL or HIGH)
    const isGenuineThreat =
      latest.is_malicious ||
      (latest.threat_level && ["HIGH", "CRITICAL"].includes(latest.threat_level.toUpperCase()));

    // Update Live Alert Feed if genuine threat (benign traffic is never added)
    if (isGenuineThreat) {
      const sev = (latest.threat_level || "HIGH").toLowerCase();
      const newAlert = {
        id: latest.id,
        severity: sev === "critical" ? "high" : (sev === "medium" ? "medium" : "high"),
        icon: ALERT_ICONS[sev] || ALERT_ICONS.high,
        message: `${(latest.threat_level || "ALERT").toUpperCase()}: ${latest.attack_type || "SUSPICIOUS"} from ${latest.src_ip || "unknown"} (${latest.protocol || "TCP"})`,
      };
      setLiveAlerts((prev) => [newAlert, ...prev.filter((a) => a.id !== latest.id)].slice(0, 6));
    }

    // Update Recent Indicators table
    const scoreVal = latest.score !== undefined ? latest.score : (latest.threat_score ? (latest.threat_score <= 1.0 ? latest.threat_score * 100 : latest.threat_score) : 0);
    const newIndicator = {
      id: latest.id,
      time: latest.timestamp ? new Date(latest.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "--:--",
      ip: latest.src_ip || "Unknown",
      type: latest.attack_type || "BENIGN",
      attack_type: latest.attack_type || "BENIGN",
      score: Math.round(scoreVal),
      severity: latest.threat_level ? latest.threat_level.charAt(0).toUpperCase() + latest.threat_level.slice(1).toLowerCase() : "Low",
      decision: latest.decision || (latest.threat_score >= 0.8 ? "BLOCK" : (latest.threat_score >= 0.5 ? "ALERT" : "ALLOW")),
    };
    setRecentThreats((prev) => [newIndicator, ...prev.filter((t) => t.id !== latest.id)].slice(0, 8));

    // Update summary counts incrementally
    setSummary((prev) => {
      const isHigh = ["HIGH", "CRITICAL"].includes((latest.threat_level || "").toUpperCase());
      const isMed = (latest.threat_level || "").toUpperCase() === "MEDIUM";
      const isLow = !isHigh && !isMed;

      return {
        ...prev,
        active: prev.active + (isHigh || isMed ? 1 : 0),
        high: prev.high + (isHigh ? 1 : 0),
        medium: prev.medium + (isMed ? 1 : 0),
        low: prev.low + (isLow ? 1 : 0),
        total: prev.total + 1,
      };
    });

    setLastUpdated(new Date());
  }, [realtimeEvents]);

  // Fallback Polling: strictly conservative (30s) and ONLY when WebSocket is disconnected
  useEffect(() => {
    if (isConnected) return; // Event-driven updates when connected; no unnecessary polling!

    const fallbackTimer = setInterval(() => {
      loadData(false);
    }, 30000);

    return () => clearInterval(fallbackTimer);
  }, [isConnected, loadData]);

  const getSeverityColor = (severity) => {
    const s = (severity || "").toLowerCase();
    if (s === "critical" || s === "high") return "high";
    if (s === "medium") return "medium";
    return "low";
  };

  const getScoreBar = (score) => (
    <div className="threat-score-bar">
      <div
        className={`threat-score-fill ${score >= 80 ? "high" : score >= 50 ? "medium" : "low"}`}
        style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
      />
      <span className="threat-score-value">{score}</span>
    </div>
  );

  return (
    <div className="threat-wrapper">
      {/* Header */}
      <div className="threat-header">
        <div className="header-content">
          <div className="header-icon">
            <FaExclamationTriangle />
          </div>
          <div>
            <h1>Threat Analysis</h1>
            <p>Real-time threat detection, severity classification, and security monitoring</p>
          </div>
        </div>
        <div className={`live-indicator ${!isConnected ? "disconnected" : ""}`}>
          <span className={`pulse ${!isConnected ? "disconnected" : ""}`}></span>
          {isConnected ? "Live Monitoring" : "Disconnected (Fallback Active)"}
          {lastUpdated && (
            <span style={{ fontSize: "0.65rem", opacity: 0.7, marginLeft: "0.5rem" }}>
              {lastUpdated.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {/* Error & Auth Banners */}
      {error && (
        <div className="threat-error-banner">
          <div className="threat-error-content">
            <FaExclamationTriangle className="threat-error-icon" />
            <div>
              <strong>{error.type === "auth" ? "Authentication Required" : "API Communication Failure"}</strong>
              <p style={{ margin: "2px 0 0 0", fontSize: "13px", opacity: 0.9 }}>{error.message}</p>
            </div>
          </div>
          {error.type === "auth" ? (
            <Link to="/login" className="threat-retry-btn">
              <FaSignInAlt /> Sign In
            </Link>
          ) : (
            <button onClick={() => loadData(true)} className="threat-retry-btn">
              <FaSyncAlt /> Retry Connection
            </button>
          )}
        </div>
      )}

      {/* Summary Cards */}
      <div className="threat-summary">
        <div className="threat-card total">
          <div className="card-glow"></div>
          <div className="card-content">
            <div className="card-icon"><FaShieldAlt /></div>
            <div className="card-info">
              <span className="card-value">{loading ? "--" : summary.active}</span>
              <span className="card-label">Active Threats</span>
            </div>
          </div>
        </div>

        <div className="threat-card high">
          <div className="card-glow"></div>
          <div className="card-content">
            <div className="card-icon"><FaSkull /></div>
            <div className="card-info">
              <span className="card-value">{loading ? "--" : summary.high}</span>
              <span className="card-label">High Severity</span>
            </div>
          </div>
        </div>

        <div className="threat-card medium">
          <div className="card-glow"></div>
          <div className="card-content">
            <div className="card-icon"><FaExclamationTriangle /></div>
            <div className="card-info">
              <span className="card-value">{loading ? "--" : summary.medium}</span>
              <span className="card-label">Medium Severity</span>
            </div>
          </div>
        </div>

        <div className="threat-card low">
          <div className="card-glow"></div>
          <div className="card-content">
            <div className="card-icon"><FaCheckCircle /></div>
            <div className="card-info">
              <span className="card-value">{loading ? "--" : summary.low}</span>
              <span className="card-label">Low Severity</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="threat-grid">
        {/* Threat Table */}
        <div className="threat-table-card">
          <h3>
            Recent Threat Indicators
            <button
              onClick={() => loadData(false)}
              style={{ background: "none", border: "none", color: "inherit", cursor: "pointer", marginLeft: "0.5rem", opacity: 0.6 }}
              title="Refresh now"
            >
              <FaSyncAlt style={{ fontSize: "0.75rem" }} />
            </button>
          </h3>
          <table className="threat-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Threat Type</th>
                <th className="score-col">Score</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {loading && recentThreats.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: "center", padding: "28px" }}>
                    <div className="threat-spinner" style={{ margin: "0 auto 8px auto" }}></div>
                    <span style={{ color: "var(--text-muted)", fontSize: "13px" }}>Loading threat telemetry...</span>
                  </td>
                </tr>
              ) : recentThreats.length > 0 ? (
                recentThreats.map((threat, index) => (
                  <tr key={threat.id || index}>
                    <td className="time-cell">{threat.time}</td>
                    <td className="ip-cell">{threat.ip}</td>
                    <td>
                      <span className="threat-type-name">{threat.type}</span>
                      {threat.decision && threat.decision !== "ALLOW" && (
                        <span
                          className="threat-decision-badge"
                          style={{
                            marginLeft: "6px",
                            fontSize: "10px",
                            fontWeight: 700,
                            padding: "2px 6px",
                            borderRadius: "4px",
                            background: "rgba(239, 68, 68, 0.15)",
                            color: "#f87171",
                          }}
                        >
                          {threat.decision}
                        </span>
                      )}
                    </td>
                    <td className="score-col">{getScoreBar(threat.score)}</td>
                    <td>
                      <span className={`severity-badge ${getSeverityColor(threat.severity)}`}>
                        {threat.severity}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} style={{ textAlign: "center", padding: "28px", color: "var(--text-muted)" }}>
                    No threat indicator records available in current scope
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Live Alert Feed */}
        <div className="alert-feed-card">
          <h3>
            <span className="feed-pulse"></span>
            Live Alert Feed
          </h3>
          <div className="alert-list">
            {loading && liveAlerts.length === 0 ? (
              <div className="threat-loading-state">
                <div className="threat-spinner"></div>
                <span>Checking threat feed...</span>
              </div>
            ) : liveAlerts.length > 0 ? (
              liveAlerts.map((alert, index) => {
                const Icon = alert.icon;
                return (
                  <div key={alert.id || index} className={`alert-item ${alert.severity}`}>
                    <div className="alert-icon"><Icon /></div>
                    <p>{alert.message}</p>
                  </div>
                );
              })
            ) : (
              <div className="alert-item low" style={{ background: "rgba(34, 197, 94, 0.05)" }}>
                <div className="alert-icon"><FaShieldAlt /></div>
                <p>No active high/critical security alerts — honeypot sensors operational</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatAnalysis;

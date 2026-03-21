import { useState, useEffect, useCallback } from "react";
import {
  FaExclamationTriangle,
  FaShieldAlt,
  FaSkull,
  FaCheckCircle,
  FaBolt,
  FaCrosshairs,
  FaWifi,
  FaUserSecret,
  FaSyncAlt
} from "react-icons/fa";
import "../Styles/pages/ThreatAnalysis.css";

const API = "";

const ThreatAnalysis = () => {
  const [summary, setSummary] = useState({ active: 0, high: 0, medium: 0, low: 0 });
  const [recentThreats, setRecentThreats] = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  const alertIcons = { high: FaSkull, medium: FaCrosshairs, low: FaUserSecret };

  const fetchThreatData = useCallback(async () => {
    try {
      // Fetch events/traffic for threat table
      const [eventsRes, statsRes] = await Promise.all([
        fetch(`${API}/api/events?limit=20`).then(r => r.ok ? r.json() : null).catch(() => null),
        fetch(`${API}/api/stats`).then(r => r.ok ? r.json() : null).catch(() => null),
      ]);

      // /api/events returns: [{ time, ip, type, port, threat, details }, ...]
      const evArr = Array.isArray(eventsRes) ? eventsRes : [];

      // Derive numeric score from threat string
      const scoreFromThreat = (t) => {
        const u = (t || "").toUpperCase();
        if (u === "MALICIOUS") return 85;
        if (u === "SUSPICIOUS") return 55;
        return 15;
      };
      const severityFromThreat = (t) => {
        const u = (t || "").toUpperCase();
        if (u === "MALICIOUS") return "High";
        if (u === "SUSPICIOUS") return "Medium";
        return "Low";
      };

      // Build recent threats table
      const threats = evArr.slice(0, 8).map(e => ({
        time: e.time ? new Date(e.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : "--:--",
        ip: e.ip || "Unknown",
        type: e.threat || e.type || "Unknown",
        score: scoreFromThreat(e.threat),
        severity: severityFromThreat(e.threat),
      }));
      if (threats.length > 0) setRecentThreats(threats);

      // Build summary counts
      let high = 0, medium = 0, low = 0;
      evArr.forEach(e => {
        const s = scoreFromThreat(e.threat);
        if (s >= 80) high++;
        else if (s >= 40) medium++;
        else low++;
      });

      // Fall back to /api/stats for totals if no events returned
      if (evArr.length > 0) {
        setSummary({ active: evArr.length, high, medium, low });
      } else if (statsRes) {
        setSummary({
          active: statsRes.totalEvents || 0,
          high: statsRes.criticalAlerts || 0,
          medium: 0,
          low: Math.max(0, (statsRes.totalEvents || 0) - (statsRes.criticalAlerts || 0)),
        });
      }

      // Build live alerts from non-benign events
      const alerts = evArr
        .filter(e => (e.threat || "").toUpperCase() !== "BENIGN")
        .slice(0, 6)
        .map(e => {
          const severity = severityFromThreat(e.threat).toLowerCase();
          return {
            severity,
            icon: alertIcons[severity] || FaWifi,
            message: `${(e.threat || "TRAFFIC").toUpperCase()}: ${e.type || "Activity"} from ${e.ip || "unknown"} — ${e.details || ""}`.trim(),
          };
        });
      if (alerts.length > 0) setLiveAlerts(alerts);

      setLastUpdated(new Date());
      setLoading(false);
    } catch (err) {
      console.error("Threat fetch error:", err);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchThreatData();
    const interval = setInterval(fetchThreatData, 5000);
    return () => clearInterval(interval);
  }, [fetchThreatData]);

  // Fallbacks if no live data yet
  const displayThreats = recentThreats.length > 0 ? recentThreats : [
    { time: "--:--", ip: "Awaiting data...", type: "No events", score: 0, severity: "Low" },
  ];

  const displayAlerts = liveAlerts.length > 0 ? liveAlerts : [
    { severity: "low", icon: FaCheckCircle, message: "No active alerts — monitoring system healthy" },
  ];

  const getSeverityColor = (severity) => {
    const colors = { High: "high", Medium: "medium", Low: "low" };
    return colors[severity] || "low";
  };

  const getScoreBar = (score) => (
    <div className="score-bar">
      <div
        className={`score-fill ${score >= 80 ? "high" : score >= 50 ? "medium" : "low"}`}
        style={{ width: `${score}%` }}
      />
      <span className="score-value">{score}</span>
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
        <div className="live-indicator">
          <span className="pulse"></span>
          Live Monitoring
          {lastUpdated && (
            <span style={{ fontSize: "0.65rem", opacity: 0.7, marginLeft: "0.5rem" }}>
              {lastUpdated.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {/* Summary Cards */}
      <div className="threat-summary">
        <div className="threat-card total">
          <div className="card-glow"></div>
          <div className="card-content">
            <div className="card-icon"><FaShieldAlt /></div>
            <div className="card-info">
              <span className="card-value">{summary.active}</span>
              <span className="card-label">Active Threats</span>
            </div>
          </div>
        </div>

        <div className="threat-card high">
          <div className="card-glow"></div>
          <div className="card-content">
            <div className="card-icon"><FaSkull /></div>
            <div className="card-info">
              <span className="card-value">{summary.high}</span>
              <span className="card-label">High Severity</span>
            </div>
          </div>
        </div>

        <div className="threat-card medium">
          <div className="card-glow"></div>
          <div className="card-content">
            <div className="card-icon"><FaExclamationTriangle /></div>
            <div className="card-info">
              <span className="card-value">{summary.medium}</span>
              <span className="card-label">Medium Severity</span>
            </div>
          </div>
        </div>

        <div className="threat-card low">
          <div className="card-glow"></div>
          <div className="card-content">
            <div className="card-icon"><FaCheckCircle /></div>
            <div className="card-info">
              <span className="card-value">{summary.low}</span>
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
              onClick={fetchThreatData}
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
              {displayThreats.map((threat, index) => (
                <tr key={index}>
                  <td className="time-cell">{threat.time}</td>
                  <td className="ip-cell">{threat.ip}</td>
                  <td>{threat.type}</td>
                  <td className="score-col">{getScoreBar(threat.score)}</td>
                  <td>
                    <span className={`severity-badge ${getSeverityColor(threat.severity)}`}>
                      {threat.severity}
                    </span>
                  </td>
                </tr>
              ))}
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
            {displayAlerts.map((alert, index) => {
              const Icon = alert.icon;
              return (
                <div key={index} className={`alert-item ${alert.severity}`}>
                  <div className="alert-icon"><Icon /></div>
                  <p>{alert.message}</p>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatAnalysis;

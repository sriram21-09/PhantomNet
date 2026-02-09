import {
  FaExclamationTriangle,
  FaShieldAlt,
  FaSkull,
  FaCheckCircle,
  FaBolt,
  FaCrosshairs,
  FaWifi,
  FaUserSecret
} from "react-icons/fa";
import "./ThreatAnalysis.css";

const ThreatAnalysis = () => {
  const summary = {
    active: 27,
    high: 6,
    medium: 14,
    low: 7,
  };

  const recentThreats = [
    { time: "10:42 AM", ip: "192.168.1.23", type: "SSH Brute Force", score: 92, severity: "High" },
    { time: "10:38 AM", ip: "45.33.21.9", type: "Port Scan", score: 68, severity: "Medium" },
    { time: "10:30 AM", ip: "172.16.4.11", type: "Anomalous Traffic", score: 55, severity: "Medium" },
    { time: "10:18 AM", ip: "10.0.0.8", type: "Suspicious Login", score: 34, severity: "Low" },
    { time: "10:05 AM", ip: "203.45.12.89", type: "DDoS Attempt", score: 88, severity: "High" },
    { time: "09:52 AM", ip: "91.203.145.2", type: "Malware Signature", score: 95, severity: "High" },
  ];

  const liveAlerts = [
    { severity: "high", icon: FaSkull, message: "Critical: SSH brute-force attack in progress from 192.168.1.23" },
    { severity: "high", icon: FaBolt, message: "DDoS traffic spike detected on port 80" },
    { severity: "medium", icon: FaCrosshairs, message: "Repeated port scans from external IP range" },
    { severity: "medium", icon: FaWifi, message: "Unusual outbound traffic pattern detected" },
    { severity: "low", icon: FaUserSecret, message: "Failed authentication attempts from internal host" },
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
          <h3>Recent Threat Indicators</h3>
          <table className="threat-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Threat Type</th>
                <th>Score</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {recentThreats.map((threat, index) => (
                <tr key={index}>
                  <td className="time-cell">{threat.time}</td>
                  <td className="ip-cell">{threat.ip}</td>
                  <td>{threat.type}</td>
                  <td>{getScoreBar(threat.score)}</td>
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
            {liveAlerts.map((alert, index) => {
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

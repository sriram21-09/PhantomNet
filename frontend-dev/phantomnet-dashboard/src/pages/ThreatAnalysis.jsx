import "./ThreatAnalysis.css";

const ThreatAnalysis = () => {
  // 🔹 Mock threat data (realistic SOC-style)
  const summary = {
    active: 27,
    high: 6,
    medium: 14,
    low: 7,
  };

  const recentThreats = [
    {
      time: "10:42 AM",
      ip: "192.168.1.23",
      type: "SSH Brute Force",
      score: 92,
      severity: "High",
    },
    {
      time: "10:38 AM",
      ip: "45.33.21.9",
      type: "Port Scan",
      score: 68,
      severity: "Medium",
    },
    {
      time: "10:30 AM",
      ip: "172.16.4.11",
      type: "Anomalous Traffic",
      score: 55,
      severity: "Medium",
    },
    {
      time: "10:18 AM",
      ip: "10.0.0.8",
      type: "Suspicious Login",
      score: 34,
      severity: "Low",
    },
  ];

  return (
    <div className="page-container threat-container">
      {/* =========================
          HEADER
      ========================== */}
      <div className="threat-header">
        <h1>Threat Analysis</h1>
        <p>
          Real-time threat indicators, anomaly detection results,
          and severity analysis across monitored systems.
        </p>
      </div>

      {/* =========================
          SUMMARY CARDS
      ========================== */}
      <div className="threat-summary">
        <div className="threat-card">
          <span>Active Threats</span>
          <h2>{summary.active}</h2>
        </div>

        <div className="threat-card high">
          <span>High Severity</span>
          <h2>{summary.high}</h2>
        </div>

        <div className="threat-card medium">
          <span>Medium Severity</span>
          <h2>{summary.medium}</h2>
        </div>

        <div className="threat-card low">
          <span>Low Severity</span>
          <h2>{summary.low}</h2>
        </div>
      </div>

      {/* =========================
          RECENT THREATS TABLE
      ========================== */}
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
                <td>{threat.time}</td>
                <td>{threat.ip}</td>
                <td>{threat.type}</td>
                <td>{threat.score}</td>
                <td>
                  <span
                    className={`severity-badge ${threat.severity.toLowerCase()}`}
                  >
                    {threat.severity}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* =========================
          ALERT FEED
      ========================== */}
      <div className="alert-feed">
        <h3>Live Alert Feed</h3>

        <div className="alert high">
          🚨 High severity SSH brute-force activity detected
        </div>

        <div className="alert medium">
          ⚠️ Repeated port scans from external IP
        </div>

        <div className="alert low">
          ℹ️ Unusual login pattern observed
        </div>
      </div>
    </div>
  );
};

export default ThreatAnalysis;

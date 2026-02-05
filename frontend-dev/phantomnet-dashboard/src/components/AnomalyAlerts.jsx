/**
 * Anomaly Alerts
 * --------------
 * Displays recent anomaly alerts detected by the system.
 * Designed for SOC analysts (clear, subtle, readable).
 */

const AnomalyAlerts = () => {
  /**
   * Mock alert data
   * (Replace with real API later)
   */
  const alerts = [
    {
      id: 1,
      source: "SSH Honeypot",
      description: "Multiple failed login attempts detected",
      severity: "high",
      score: 82,
      time: "2 mins ago",
    },
    {
      id: 2,
      source: "HTTP Honeypot",
      description: "Unusual request pattern observed",
      severity: "medium",
      score: 61,
      time: "6 mins ago",
    },
    {
      id: 3,
      source: "FTP Honeypot",
      description: "Abnormal file access behavior",
      severity: "medium",
      score: 58,
      time: "12 mins ago",
    },
    {
      id: 4,
      source: "Network Switch",
      description: "Unexpected traffic spike detected",
      severity: "low",
      score: 42,
      time: "18 mins ago",
    },
  ];

  return (
    <div className="anomaly-alerts">
      {alerts.map((alert) => (
        <div key={alert.id} className="anomaly-alert-card">
          {/* LEFT: Severity Indicator */}
          <div
            className={`severity-dot severity-${alert.severity}`}
            title={`Severity: ${alert.severity}`}
          />

          {/* MIDDLE: Alert Info */}
          <div className="alert-content">
            <h4 className="alert-title">{alert.source}</h4>
            <p className="alert-description">
              {alert.description}
            </p>

            <div className="alert-meta">
              <span className="alert-time">{alert.time}</span>
              <span className="alert-score">
                Score: {alert.score}%
              </span>
            </div>
          </div>

          {/* RIGHT: Severity Label */}
          <div
            className={`alert-severity-label severity-${alert.severity}`}
          >
            {alert.severity.toUpperCase()}
          </div>
        </div>
      ))}
    </div>
  );
};

export default AnomalyAlerts;

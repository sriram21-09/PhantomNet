import React, { useState, useEffect } from 'react';

const AnomalyAlerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchAlerts = async () => {
    try {
      const res = await fetch('/api/v1/alerts?limit=10');
      if (res.ok) {
        const data = await res.json();
        setAlerts(data.alerts || []);
      }
    } catch (err) {
      console.error("Failed to fetch alerts:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  const formatSource = (type, ip) => {
    const formattedType = type.split('_').map(word => 
      word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
    ).join(' ');
    return ip ? `${formattedType} (${ip})` : formattedType;
  };

  const getScore = (level) => {
    const l = level.toUpperCase();
    if (l === 'CRITICAL') return 92;
    if (l === 'HIGH') return 78;
    if (l === 'MEDIUM') return 55;
    return 35;
  };

  const formatTime = (timeStr) => {
    const d = new Date(timeStr);
    const now = new Date();
    const diffMs = now - d;
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return 'Just now';
    if (diffMins === 1) return '1 min ago';
    if (diffMins < 60) return `${diffMins} mins ago`;
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  if (loading && alerts.length === 0) {
    return <div className="text-slate-500 text-center py-4 hud-font">Loading alerts...</div>;
  }

  if (alerts.length === 0) {
    return <div className="text-slate-500 text-center py-4 hud-font">No active security alerts</div>;
  }

  return (
    <div className="anomaly-alerts">
      {alerts.map((alert) => {
        const severity = alert.level.toLowerCase();
        return (
          <div key={alert.id} className="anomaly-alert-card">
            {/* LEFT: Severity Indicator */}
            <div
              className={`severity-dot severity-${severity}`}
              title={`Severity: ${alert.level}`}
            />

            {/* MIDDLE: Alert Info */}
            <div className="alert-content">
              <h4 className="alert-title">{formatSource(alert.type, alert.source_ip)}</h4>
              <p className="alert-description">
                {alert.description}
              </p>

              <div className="alert-meta">
                <span className="alert-time">{formatTime(alert.timestamp)}</span>
                <span className="alert-score">
                  Score: {getScore(alert.level)}%
                </span>
              </div>
            </div>

            {/* RIGHT: Severity Label */}
            <div
              className={`alert-severity-label severity-${severity}`}
            >
              {alert.level.toUpperCase()}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default AnomalyAlerts;

import React from 'react';

const AnomalyAlerts = ({ recentAnomalies = [], loading = false, error = null, onRetry }) => {
  const formatSource = (type, ip) => {
    if (!type && !ip) return "Unknown Event";
    const formattedType = (type || "ANOMALY")
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(' ');
    return ip ? `${formattedType} (${ip})` : formattedType;
  };

  const formatScore = (score) => {
    if (score === undefined || score === null) return "0.0";
    const num = Number(score);
    if (isNaN(num)) return "0.0";
    return num <= 1.0 && num > 0 ? (num * 100).toFixed(1) : num.toFixed(1);
  };

  const formatTime = (timeStr) => {
    if (!timeStr) return "--:--";
    const d = new Date(timeStr);
    if (isNaN(d.getTime())) return String(timeStr);
    const now = new Date();
    const diffMs = now - d;
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return 'Just now';
    if (diffMins === 1) return '1 min ago';
    if (diffMins < 60) return `${diffMins} mins ago`;
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  if (loading && (!recentAnomalies || recentAnomalies.length === 0)) {
    return <div className="text-slate-500 text-center py-4 hud-font">Loading anomaly feed...</div>;
  }

  if (error && (!recentAnomalies || recentAnomalies.length === 0)) {
    return (
      <div className="anomaly-error-box text-center py-4 hud-font">
        <p className="text-red-400 mb-2">{error}</p>
        {onRetry && (
          <button className="anomaly-retry-btn hud-font" onClick={onRetry}>
            Retry Feed
          </button>
        )}
      </div>
    );
  }

  if (!recentAnomalies || recentAnomalies.length === 0) {
    return <div className="text-slate-500 text-center py-4 hud-font">No anomaly records detected in this scope</div>;
  }

  return (
    <div className="anomaly-alerts">
      {recentAnomalies.map((alert) => {
        const severity = (alert.level || 'medium').toLowerCase();
        return (
          <div key={alert.id} className="anomaly-alert-card">
            {/* LEFT: Severity Indicator */}
            <div
              className={`severity-dot severity-${severity}`}
              title={`Severity: ${alert.level || 'MEDIUM'}`}
            />

            {/* MIDDLE: Alert Info */}
            <div className="alert-content">
              <h4 className="alert-title">{formatSource(alert.type || alert.protocol, alert.source_ip)}</h4>
              <p className="alert-description">
                {alert.description}
              </p>

              <div className="alert-meta">
                <span className="alert-time">{formatTime(alert.timestamp)}</span>
                <span className="alert-score">
                  ML Anomaly Score: {formatScore(alert.score)}%
                </span>
              </div>
            </div>

            {/* RIGHT: Severity Label */}
            <div
              className={`alert-severity-label severity-${severity}`}
            >
              {(alert.level || 'MEDIUM').toUpperCase()}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default AnomalyAlerts;

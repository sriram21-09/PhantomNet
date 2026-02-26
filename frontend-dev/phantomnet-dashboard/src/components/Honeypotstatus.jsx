import React, { useEffect, useState } from "react";
import { FaLock, FaGlobe, FaFolder, FaEnvelope } from "react-icons/fa";
import "./HoneypotStatus.css";

const iconMap = {
  SSH: FaLock,
  HTTP: FaGlobe,
  FTP: FaFolder,
  SMTP: FaEnvelope,
  MYSQL: FaLock, // Using FaLock for DB as well, or could use another
};

// Format last_seen as relative time
const formatLastSeen = (lastSeen) => {
  if (!lastSeen || lastSeen === "Never") return "—";

  try {
    // The backend returns UTC timestamps in format "YYYY-MM-DD HH:MM:SS"
    // Append 'Z' to indicate UTC, or replace space with 'T' for ISO format
    let isoString = lastSeen;
    if (!lastSeen.includes('T') && !lastSeen.includes('Z')) {
      // Convert "2026-02-09 11:02:47" to "2026-02-09T11:02:47Z"
      isoString = lastSeen.replace(' ', 'T') + 'Z';
    }

    const lastSeenDate = new Date(isoString);
    const now = new Date();
    const diffMs = now.getTime() - lastSeenDate.getTime();
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);

    if (diffSecs < 0) return "Just now"; // Handle clock skew
    if (diffSecs < 60) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;

    // For older timestamps, show time only (convert to local time)
    const localTime = lastSeenDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    return localTime;
  } catch {
    return lastSeen.split(" ")[1] || "—";
  }
};

const HoneypotStatus = () => {
  const [honeypots, setHoneypots] = useState([]);
  const [error, setError] = useState(null);

  const fetchHoneypots = async () => {
    try {
      const res = await fetch("/api/honeypots");
      if (!res.ok) throw new Error();
      setHoneypots(await res.json());
      setError(null);
    } catch {
      setError("Service unavailable");
    }
  };

  useEffect(() => {
    fetchHoneypots();
    const interval = setInterval(fetchHoneypots, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="honeypot-monitor-container pro-card">
      <div className="monitor-header hud-font">
        <div className="monitor-title">
          <h3 className="glow-text">Honeypot Network Status</h3>
          <p className="text-dim">Global Sensing Grid • Real-time Health</p>
        </div>
        <div className="status-summary">
          <span className="summary-dot"></span>
          <span className="summary-text">
            {honeypots.filter(h => h.status === 'active').length}/{honeypots.length} SCANNING
          </span>
        </div>
      </div>

      {error && <div className="monitor-error">{error}</div>}

      <div className="status-scroller">
        {honeypots.map((hp) => {
          const Icon = iconMap[hp.name] || FaGlobe;
          const isActive = hp.status === "active";

          return (
            <div key={hp.name} className={`status-row ${isActive ? "active" : "inactive"}`}>
              <div className="row-glass"></div>
              <div className="status-row-content">
                <div className="row-icon-side">
                  <div className="row-icon-box">
                    <Icon />
                  </div>
                  <div className="health-ring"></div>
                </div>

                <div className="row-info-main">
                  <div className="row-top">
                    <span className="hp-name">{hp.name} Service</span>
                    <div className={`status-badge-new ${isActive ? "online" : "offline"}`}>
                      <span className="badge-pulse"></span>
                      {isActive ? "STABLE" : "SIGNAL LOST"}
                    </div>
                  </div>
                  <div className="row-bottom">
                    <span className="detail-item">NODE_ID: {hp.name.toUpperCase()}</span>
                    <span className="detail-separator">|</span>
                    <span className="detail-item">PORT: {hp.port}</span>
                    <span className="detail-separator">|</span>
                    <span className="detail-item">LAST_PING: {formatLastSeen(hp.last_seen)}</span>
                  </div>
                </div>

                <div className="row-action-side">
                  <div className="pulse-indicator-container">
                    <div className={`ping-pulse ${isActive ? 'active' : ''}`}></div>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default HoneypotStatus;

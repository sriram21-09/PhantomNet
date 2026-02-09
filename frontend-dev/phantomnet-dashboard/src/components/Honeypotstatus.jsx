import { useEffect, useState } from "react";
import { FaLock, FaGlobe, FaFolder, FaEnvelope } from "react-icons/fa";
import "./HoneypotStatus.css";

const iconMap = {
  SSH: FaLock,
  HTTP: FaGlobe,
  FTP: FaFolder,
  SMTP: FaEnvelope,
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
    <div className="honeypot-wrapper">
      <div className="honeypot-header">
        <h3>Honeypot Status</h3>
        <span className="live-badge">
          <span className="live-dot"></span>
          Live
        </span>
      </div>

      {error && <div className="honeypot-error">{error}</div>}

      <div className="honeypot-list">
        {honeypots.map((hp) => {
          const Icon = iconMap[hp.name] || FaGlobe;
          const isActive = hp.status === "active";

          return (
            <div key={hp.name} className={`honeypot-item ${isActive ? "active" : "inactive"}`}>
              <div className="honeypot-icon">
                <Icon />
              </div>
              <div className="honeypot-info">
                <div className="honeypot-name">
                  <span>{hp.name}</span>
                  <span className={`status-badge ${isActive ? "online" : "offline"}`}>
                    {isActive ? "ONLINE" : "OFFLINE"}
                  </span>
                </div>
                <div className="honeypot-details">
                  Port: {hp.port} • Last: {formatLastSeen(hp.last_seen)}
                </div>
              </div>
              <div className={`status-indicator ${isActive ? "active" : ""}`}></div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default HoneypotStatus;

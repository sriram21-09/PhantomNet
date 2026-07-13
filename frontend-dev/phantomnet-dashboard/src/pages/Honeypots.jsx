import React, { useState, useEffect } from "react";
import { FaTerminal, FaGlobe, FaDatabase, FaEnvelope, FaServer } from "react-icons/fa";
import "../Styles/pages/Honeypots.css";

const formatLastSeen = (lastSeen) => {
  if (!lastSeen || lastSeen === "Never") return "Never";
  try {
    const lastSeenDate = new Date(lastSeen);
    const now = new Date();
    const diffMs = now.getTime() - lastSeenDate.getTime();
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffSecs < 60) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return lastSeenDate.toLocaleDateString();
  } catch (err) {
    return "Never";
  }
};

const HoneypotCard = ({ title, port, status, icon: Icon, description, lastSeen, packetCount }) => (
  <div className={`honeypot-card ${status.toLowerCase()}`}>
    <div className="scan-line"></div>
    <div className="card-header">
      <div className="icon-box">
        <Icon />
      </div>
      <div className="status-indicator">
        <div className="status-dot"></div>
        <span className="hud-font">{status.toUpperCase()}</span>
      </div>
    </div>
    <div className="card-body">
      <h3>{title}</h3>
      <p className="description" style={{ fontSize: '0.875rem', color: '#94a3b8', margin: '0.5rem 0 1rem 0' }}>{description}</p>
      
      <div className="info-row">
        <span className="info-label">LISTENING PORT</span>
        <span className="info-value hud-font">{port}</span>
      </div>
      <div className="info-row">
        <span className="info-label">CAPTURED LOGS</span>
        <span className="info-value value-highlight hud-font">{packetCount}</span>
      </div>
      <div className="info-row">
        <span className="info-label">LAST ACTIVE</span>
        <span className="info-value text-dim hud-font">{lastSeen}</span>
      </div>
    </div>
  </div>
);

const Honeypots = () => {
  const [honeypots, setHoneypots] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchHoneypotStatus = async () => {
      try {
        const res = await fetch("http://localhost:8000/api/honeypots");
        const data = await res.json();

        // Icon map
        const iconMap = {
          SSH: FaTerminal,
          HTTP: FaGlobe,
          FTP: FaServer,
          SMTP: FaEnvelope,
        };

        // Description map
        const descMap = {
          SSH: "Advanced session logging and brute-force detection.",
          HTTP: "Simulated admin panels and web application traps.",
          FTP: "Directory traversal and file access monitoring.",
          SMTP: "Email spoofing and spam trap environment.",
        };

        if (Array.isArray(data)) {
          const mapped = data.map(hp => ({
            title: `${hp.name} Honeypot`,
            port: hp.port.toString(),
            status: hp.status === "active" ? "ACTIVE" : "INACTIVE",
            icon: iconMap[hp.name] || FaServer,
            description: descMap[hp.name] || "Deception listening environment.",
            lastSeen: formatLastSeen(hp.last_seen),
            packetCount: hp.packet_count || 0
          }));
          
          // Append planned honeypot for roadmap visual representation
          mapped.push({
            title: "Database Honeypot",
            port: "3306",
            status: "PLANNED",
            icon: FaDatabase,
            description: "SQL injection and credential theft detection.",
            lastSeen: "Not Scheduled",
            packetCount: 0
          });

          setHoneypots(mapped);
        }
      } catch (err) {
        console.error("Failed to load honeypots status:", err);
      } finally {
        setIsLoading(false);
      }
    };

    fetchHoneypotStatus();
    const interval = setInterval(fetchHoneypotStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  if (isLoading) {
    return (
      <div className="dashboard-wrapper loading-container">
        <div className="loading-spinner"></div>
        <div className="loading-text hud-font">QUERYING DECEPTION MESH STATE...</div>
      </div>
    );
  }

  return (
    <div className="honeypots-wrapper">
      <div className="honeypots-header">
        <div className="header-badge hud-font">DECEPTION_GRID_V2.0</div>
        <h1 className="honeypots-title glow-text">Honeypot Network</h1>
        <p className="honeypots-subtitle text-dim">LIVE STATUS | ACTIVE DEFENSE DECEPTION TOPOLOGY</p>
      </div>

      <div className="honeypots-grid">
        {honeypots.map((service, idx) => (
          <HoneypotCard key={idx} {...service} />
        ))}
      </div>
    </div>
  );
};

export default Honeypots;
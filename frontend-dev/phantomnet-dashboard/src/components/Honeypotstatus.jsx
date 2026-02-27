import React, { useEffect, useState } from "react";
import {
  FaLock, FaGlobe, FaFolder, FaEnvelope,
  FaServer, FaNetworkWired
} from "react-icons/fa";
import "./HoneypotStatus.css";

const iconMap = {
  SSH: FaLock,
  HTTP: FaGlobe,
  FTP: FaFolder,
  SMTP: FaEnvelope,
  MYSQL: FaServer,
};

const formatLastSeen = (lastSeen) => {
  if (!lastSeen || lastSeen === "Never") return "—";
  try {
    let isoString = lastSeen;
    if (!lastSeen.includes("T") && !lastSeen.includes("Z")) {
      isoString = lastSeen.replace(" ", "T") + "Z";
    }
    const lastSeenDate = new Date(isoString);
    const now = new Date();
    const diffMs = now.getTime() - lastSeenDate.getTime();
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    if (diffSecs < 0) return "Just now";
    if (diffSecs < 60) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return lastSeenDate.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false });
  } catch {
    return lastSeen.split(" ")[1] || "—";
  }
};

// Static infrastructure nodes (left panel)
const INFRA_NODES = [
  { id: "controller", label: "Controller", sub: "Primary Node • 127.0.0.1", status: "ONLINE", color: "#22c55e" },
  { id: "switch", label: "Core Switch", sub: "VLAN 10, 20 Traffic", status: "ACTIVE", color: "#3b82f6" },
];

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

  const activeCount = honeypots.filter((h) => h.status === "active").length;

  return (
    <div className="hps-wrapper">
      {/* ── LEFT: Infrastructure ── */}
      <div className="hps-infra-panel">
        <div className="hps-panel-header hud-font">
          <span className="hps-panel-label">NETWORK INFRASTRUCTURE</span>
        </div>
        <div className="hps-infra-list">
          {INFRA_NODES.map((node) => (
            <div key={node.id} className="hps-infra-card">
              <div className="hps-infra-icon">
                <FaNetworkWired />
              </div>
              <div className="hps-infra-info">
                <span className="hps-infra-name">{node.label}</span>
                <span className="hps-infra-sub">{node.sub}</span>
              </div>
              <div className="hps-infra-badge" style={{ color: node.color, borderColor: node.color }}>
                {node.status}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── RIGHT: Honeypot Grid ── */}
      <div className="hps-honeypot-panel">
        <div className="hps-panel-header hud-font">
          <span className="hps-panel-label">
            <span className="hps-panel-accent">|</span> ACTIVE ASSET NODES (HONEYPOTS)
          </span>
          <span className="hps-scan-badge">
            <span className="hps-scan-dot" />
            {activeCount}/{honeypots.length} SCANNING
          </span>
        </div>

        {error && <div className="hps-error">{error}</div>}

        <div className="hps-honeypot-grid">
          {honeypots.map((hp) => {
            const Icon = iconMap[hp.name] || FaGlobe;
            const isActive = hp.status === "active";
            return (
              <div key={hp.name} className={`hps-hp-card ${isActive ? "hp-active" : "hp-inactive"}`}>
                <div className="hps-hp-top">
                  <div className={`hps-hp-icon ${isActive ? "icon-on" : "icon-off"}`}>
                    <Icon />
                  </div>
                  <div className="hps-hp-meta">
                    <span className="hps-hp-name">{hp.name}</span>
                    <span className="hps-hp-port">PORT {hp.port}</span>
                  </div>
                </div>
                <div className="hps-hp-activity">
                  {[...Array(7)].map((_, i) => (
                    <span
                      key={i}
                      className={`hps-bar ${isActive && i < 4 ? "bar-lit" : ""}`}
                      style={{ height: `${6 + Math.random() * 8}px` }}
                    />
                  ))}
                </div>
                <div className="hps-hp-bottom">
                  <span className="hps-pkts-val">{hp.total_events ?? 0}</span>
                  <span className="hps-pkts-lbl">PKTS</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default HoneypotStatus;

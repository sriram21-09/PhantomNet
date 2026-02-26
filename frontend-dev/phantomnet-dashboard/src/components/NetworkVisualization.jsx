import React, { useEffect, useState } from "react";
import {
  FaServer,
  FaNetworkWired,
  FaLock,
  FaGlobe,
  FaFolder,
  FaEnvelope,
} from "react-icons/fa";
import "./NetworkVisualization.css";

const NetworkVisualization = () => {
  const [nodes, setNodes] = useState({
    ssh: { count: 0, status: "inactive" },
    http: { count: 0, status: "inactive" },
    ftp: { count: 0, status: "inactive" },
    smtp: { count: 0, status: "inactive" },
    mysql: { count: 0, status: "inactive" },
  });

  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await fetch("/api/honeypots/status");
        if (!res.ok) throw new Error("Failed to fetch");
        const data = await res.json();

        const nodeMap = {
          ssh: { count: 0, status: "inactive" },
          http: { count: 0, status: "inactive" },
          ftp: { count: 0, status: "inactive" },
          smtp: { count: 0, status: "inactive" },
          mysql: { count: 0, status: "inactive" },
        };

        data.forEach((service) => {
          const key = service.name.toLowerCase();
          if (nodeMap[key]) {
            nodeMap[key] = {
              count: service.packet_count || 0,
              status: service.status,
            };
          }
        });

        setNodes(nodeMap);
      } catch (err) {
        console.error("Network Viz Error:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  const honeypots = [
    { key: "ssh", name: "SSH", icon: FaLock, port: 2222 },
    { key: "http", name: "HTTP", icon: FaGlobe, port: 8080 },
    { key: "ftp", name: "FTP", icon: FaFolder, port: 2121 },
    { key: "smtp", name: "SMTP", icon: FaEnvelope, port: 2525 },
  ];

  if (loading) {
    return (
      <div className="network-wrapper">
        <div className="network-header">
          <h3>Live Mesh Topology</h3>
          <span className="refresh-info">Initializing...</span>
        </div>
        <div className="network-loading">
          <div className="pulse-ring"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="network-visualization-container pro-card">
      <div className="network-header">
        <div className="header-icon-group">
          <div className="network-main-icon"><FaNetworkWired /></div>
          <div className="header-text">
            <h3>Live Mesh Topology</h3>
            <span className="refresh-info">Real-time Node Monitoring • 2s refresh</span>
          </div>
        </div>
        <div className="system-health-badge">
          <span className="pulse-dot"></span>
          SYSTEM OPTIMAL
        </div>
      </div>

      <div className="viz-content-grid">
        {/* Core Infrastructure Section */}
        <div className="infra-section">
          <div className="hud-label">CORE INFRASTRUCTURE</div>
          <div className="core-stack">
            <div className="core-hud-card controller">
              <div className="hud-corner top-left"></div>
              <div className="hud-corner bottom-right"></div>
              <div className="core-hud-content">
                <div className="core-hud-icon"><FaServer /></div>
                <div className="core-hud-info">
                  <span className="core-name">Controller</span>
                  <span className="core-desc">Primary Node • 127.0.0.1</span>
                </div>
                <div className="core-hud-status active">ONLINE</div>
              </div>
            </div>

            <div className="core-hud-card switch">
              <div className="hud-corner top-right"></div>
              <div className="hud-corner bottom-left"></div>
              <div className="core-hud-content">
                <div className="core-hud-icon"><FaNetworkWired /></div>
                <div className="core-hud-info">
                  <span className="core-name">Core Switch</span>
                  <span className="core-desc">VLAN 10, 20 Traffic</span>
                </div>
                <div className="core-hud-status active">ACTIVE</div>
              </div>
            </div>
          </div>
        </div>

        {/* Honeypot Nodes Section */}
        <div className="nodes-section">
          <div className="hud-label">ACTIVE ASSET NODES (HONEYPOTS)</div>
          <div className="nodes-hud-grid">
            {honeypots.map((hp) => {
              const Icon = hp.icon;
              const nodeData = nodes[hp.key];
              const isActive = (nodeData && nodeData.status === "active");

              return (
                <div key={hp.key} className={`node-hud-card ${isActive ? "active" : "inactive"}`}>
                  <div className="node-hud-glow"></div>
                  <div className="node-hud-header">
                    <div className="node-hud-icon">
                      <Icon />
                    </div>
                    <div className="node-hud-title">
                      <span className="node-name">{hp.name}</span>
                      <span className="node-port">PORT {hp.port}</span>
                    </div>
                  </div>
                  <div className="node-hud-body">
                    <div className="data-stream-viz">
                      {[...Array(5)].map((_, i) => (
                        <div key={i} className={`stream-bit ${isActive ? 'flowing' : ''}`} style={{ animationDelay: `${i * 0.2}s` }}></div>
                      ))}
                    </div>
                    <div className="node-stats-badge">
                      <span className="stats-value">{nodeData ? nodeData.count.toLocaleString() : 0}</span>
                      <span className="stats-label">PKTS</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkVisualization;

import { useEffect, useState } from "react";
import {
  FaServer,
  FaNetworkWired,
  FaLock,
  FaGlobe,
  FaFolder,
  FaEnvelope,
} from "react-icons/fa";
import "../styles/components/NetworkVisualization.css";

const NetworkVisualization = () => {
  const [nodes, setNodes] = useState({
    ssh: { count: 0, status: "inactive" },
    http: { count: 0, status: "inactive" },
    ftp: { count: 0, status: "inactive" },
    smtp: { count: 0, status: "inactive" },
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
    <div className="network-wrapper">
      <div className="network-header">
        <h3>Live Mesh Topology</h3>
        <span className="refresh-info">Real-time • 2s refresh</span>
      </div>

      {/* Core Infrastructure */}
      <div className="core-grid">
        <div className="core-card controller">
          <div className="core-glow"></div>
          <div className="core-content">
            <div className="core-icon">
              <FaServer />
            </div>
            <div className="core-info">
              <h4>Controller</h4>
              <p>Primary Node • Online</p>
            </div>
            <div className="core-status active"></div>
          </div>
        </div>

        <div className="core-card switch">
          <div className="core-glow"></div>
          <div className="core-content">
            <div className="core-icon">
              <FaNetworkWired />
            </div>
            <div className="core-info">
              <h4>Switch</h4>
              <p>VLAN 10, 20</p>
            </div>
            <div className="core-status active"></div>
          </div>
        </div>
      </div>

      {/* Honeypot Nodes */}
      <div className="nodes-grid">
        {honeypots.map((hp) => {
          const Icon = hp.icon;
          const nodeData = nodes[hp.key];
          const isActive = nodeData.status === "active";

          return (
            <div key={hp.key} className={`node-card ${isActive ? "active" : "inactive"}`}>
              {isActive && <div className="node-glow"></div>}
              <div className="node-content">
                <div className={`node-icon ${isActive ? "active" : ""}`}>
                  <Icon />
                </div>
                <h4>{hp.name}</h4>
                <p className="node-port">Port {hp.port}</p>
                <div className={`node-badge ${isActive ? "active" : ""}`}>
                  <span className="badge-dot"></span>
                  {nodeData.count.toLocaleString()} pkts
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default NetworkVisualization;

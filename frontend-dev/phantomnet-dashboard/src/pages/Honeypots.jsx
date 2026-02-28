import React from "react";
import { FaShieldAlt, FaTerminal, FaGlobe, FaDatabase, FaEnvelope, FaServer } from "react-icons/fa";
import "../Styles/pages/Honeypots.css";

const HoneypotCard = ({ title, port, status, icon: Icon, description }) => (
  <div className="honeypot-card">
    <div className="scan-line"></div>
    <div className="card-header">
      <div className="icon-box">
        <Icon />
      </div>
      <div className="status-indicator">
        <div className="status-dot"></div>
        <span>{status}</span>
      </div>
    </div>
    <div className="card-body">
      <h3>{title}</h3>
      <p className="description" style={{ fontSize: '0.875rem', color: '#94a3b8', margin: '0.5rem 0 1rem 0' }}>{description}</p>
      <div className="info-row">
        <span className="info-label">LISTENING PORT</span>
        <span className="info-value">{port}</span>
      </div>
      <div className="info-row">
        <span className="info-label">PROTOCOL</span>
        <span className="info-value">{title.split(' ')[0]}</span>
      </div>
    </div>
  </div>
);

const Honeypots = () => {
  const services = [
    { title: "SSH Honeypot", port: "2222", status: "ACTIVE", icon: FaTerminal, description: "Advanced session logging and brute-force detection." },
    { title: "HTTP Honeypot", port: "8080", status: "ACTIVE", icon: FaGlobe, description: "Simulated admin panels and web application traps." },
    { title: "FTP Honeypot", port: "2121", status: "ACTIVE", icon: FaServer, description: "Directory traversal and file access monitoring." },
    { title: "SMTP Honeypot", port: "2525", status: "ACTIVE", icon: FaEnvelope, description: "Email spoofing and spam trap environment." },
    { title: "DB Honeypot", port: "3306", status: "PLANNED", icon: FaDatabase, description: "SQL injection and credential theft detection." },
  ];

  return (
    <div className="honeypots-wrapper">
      <div className="honeypots-header">
        <h1 className="honeypots-title">Honeypot Network</h1>
        <p className="honeypots-subtitle">LIVE STATUS | DECEPTION MESH TOPOLOGY</p>
      </div>

      <div className="honeypots-grid">
        {services.map((service, idx) => (
          <HoneypotCard key={idx} {...service} />
        ))}
      </div>
    </div>
  );
};

export default Honeypots;
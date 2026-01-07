import React from "react";

const NetworkVisualization = () => {
  const nodes = [
    { name: "Controller", role: "Control Node", packets: 1361 },
    { name: "Switch", role: "Network Switch", packets: 1106 },
    { name: "SSH Honeypot", role: "Service Node", packets: 547 },
    { name: "HTTP Honeypot", role: "Service Node", packets: 736 },
    { name: "FTP Honeypot", role: "Service Node", packets: 431 }
  ];

  return (
    <div className="section">
      <h2>Network Topology</h2>

      <div
        style={{
          display: "flex",
          gap: "16px",
          marginTop: "16px",
          flexWrap: "wrap"
        }}
      >
        {nodes.map((node, index) => (
          <div key={index} className="card">
            <h4>{node.name}</h4>
            <p>Role: {node.role}</p>
            <p>Packets: {node.packets}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default NetworkVisualization;
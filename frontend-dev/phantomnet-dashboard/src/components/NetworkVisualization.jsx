import { useEffect, useState } from "react";
import "./network.css";

const mockTopology = [
  { id: "controller", label: "Controller", role: "Control Node", packets: 1200 },
  { id: "switch", label: "Switch", role: "Network Switch", packets: 980 },
  { id: "ssh", label: "SSH Honeypot", role: "Service Node", packets: 450 },
  { id: "http", label: "HTTP Honeypot", role: "Service Node", packets: 620 },
  { id: "ftp", label: "FTP Honeypot", role: "Service Node", packets: 300 }
];

const NetworkVisualization = () => {
  // ✅ initialize state directly
  const [nodes, setNodes] = useState(mockTopology);

  useEffect(() => {
    // ✅ effect used ONLY for external updates (timer)
    const interval = setInterval(() => {
      setNodes(prev =>
        prev.map(node => ({
          ...node,
          packets: node.packets + Math.floor(Math.random() * 20)
        }))
      );
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="network-container">
      <h2>Network Topology</h2>

      <div className="network-grid">
        {nodes.map(node => (
          <div key={node.id} className="network-node">
            <strong>{node.label}</strong>
            <p>Role: {node.role}</p>
            <p>Packets: {node.packets}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default NetworkVisualization;
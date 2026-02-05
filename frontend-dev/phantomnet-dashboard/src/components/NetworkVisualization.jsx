import {
  FaServer,
  FaNetworkWired,
  FaLock,
  FaGlobe,
  FaFolderOpen,
} from "react-icons/fa";
import "./NetworkVisualization.css";

const NetworkVisualization = () => {
  return (
    <div className="network-section">
      <h2>Network Topology</h2>

      <div className="network-grid">
        {/* Controller */}
        <div className="network-node active">
          <div className="node-header">
            <FaServer className="node-icon" />
            <span className="node-status active" />
          </div>
          <h4>Controller</h4>
          <p>Role: Control Node</p>
          <p>Packets: 1361</p>
        </div>

        {/* Switch */}
        <div className="network-node active">
          <div className="node-header">
            <FaNetworkWired className="node-icon" />
            <span className="node-status active" />
          </div>
          <h4>Switch</h4>
          <p>Role: Network Switch</p>
          <p>Packets: 1106</p>
        </div>

        {/* SSH Honeypot */}
        <div className="network-node active">
          <div className="node-header">
            <FaLock className="node-icon" />
            <span className="node-status active pulse" />
          </div>
          <h4>SSH Honeypot</h4>
          <p>Role: Service Node</p>
          <p>Packets: 547</p>
        </div>

        {/* HTTP Honeypot */}
        <div className="network-node active">
          <div className="node-header">
            <FaGlobe className="node-icon" />
            <span className="node-status active pulse" />
          </div>
          <h4>HTTP Honeypot</h4>
          <p>Role: Service Node</p>
          <p>Packets: 736</p>
        </div>

        {/* FTP Honeypot */}
        <div className="network-node idle">
          <div className="node-header">
            <FaFolderOpen className="node-icon" />
            <span className="node-status idle" />
          </div>
          <h4>FTP Honeypot</h4>
          <p>Role: Service Node</p>
          <p>Packets: 431</p>
        </div>
      </div>
    </div>
  );
};

export default NetworkVisualization;

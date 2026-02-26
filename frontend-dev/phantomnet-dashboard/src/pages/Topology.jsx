import React from "react";
import NetworkTopology from "../components/NetworkTopology";
import "../Styles/pages/Dashboard.css"; // Reuse dashboard wrapper styles if needed, or create specific ones

const Topology = () => {
    return (
        <div className="dashboard-wrapper" style={{ height: 'calc(100vh - 80px)', display: 'flex', flexDirection: 'column' }}>
            <div className="dashboard-header">
                <div className="header-content">
                    <div className="header-title">
                        <div className="dashboard-header-premium">
                            <div className="header-badge hud-font">NODE_DELTA_V.2</div>
                            <h1 className="dashboard-title glow-text">Network Topology</h1>
                            <p className="dashboard-subtitle text-dim">INFRASTRUCTURE VISUALIZATION | REAL-TIME MESH STATUS</p>
                        </div>
                    </div>
                </div>
            </div>

            <div style={{ flex: 1, minHeight: 0, marginTop: '20px' }}>
                <NetworkTopology />
            </div>
        </div>
    );
};

export default Topology;

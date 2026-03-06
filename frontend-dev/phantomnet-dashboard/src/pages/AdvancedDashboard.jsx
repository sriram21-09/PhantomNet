import React from 'react';
import { RealTimeProvider, useRealTime } from '../context/RealTimeContext';
import EventStream from '../components/EventStream';
import LiveMetrics from '../components/LiveMetrics';
import AttackAttribution from '../components/AttackAttribution';
import PredictiveAnalytics from '../components/PredictiveAnalytics';
import { Wifi, WifiOff, Shield } from 'lucide-react';
import '../Styles/pages/AdvancedDashboard.css';

const ConnectionBanner = () => {
    const { isConnected, reconnectCount } = useRealTime();
    return (
        <div className={`connection-banner ${isConnected ? 'banner-connected' : 'banner-disconnected'}`}>
            {isConnected ? <Wifi size={14} /> : <WifiOff size={14} />}
            <span>
                {isConnected
                    ? 'NEURAL LINK ESTABLISHED — ALL SYSTEMS NOMINAL'
                    : `CONNECTION LOST — RECONNECTING... (ATTEMPT ${reconnectCount})`
                }
            </span>
        </div>
    );
};

const DashboardContent = () => {
    return (
        <div className="advanced-dashboard-container">
            <div className="dashboard-header-premium">
                <div className="header-content">
                    <div className="header-badge hud-font">
                        <Shield size={12} /> PROTOCOL_ACTIVE
                    </div>
                    <h1 className="dashboard-title glow-text">Neural Operations Center</h1>
                    <p className="dashboard-subtitle text-dim">
                        REAL-TIME THREAT SYNCHRONIZATION | AI-DRIVEN PREDICTION ENGINE
                    </p>
                </div>
                <div className="header-timestamp hud-font">
                    {new Date().toLocaleDateString('en-US', { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' })}
                </div>
            </div>

            <ConnectionBanner />

            <div className="advanced-dashboard-grid">
                <div className="grid-area-metrics">
                    <LiveMetrics />
                </div>
                <div className="grid-area-predictive">
                    <PredictiveAnalytics />
                </div>
                <div className="grid-area-attribution">
                    <AttackAttribution />
                </div>
                <div className="grid-area-stream">
                    <EventStream />
                </div>
            </div>
        </div>
    );
};

const AdvancedDashboard = () => {
    return (
        <RealTimeProvider>
            <DashboardContent />
        </RealTimeProvider>
    );
};

export default AdvancedDashboard;

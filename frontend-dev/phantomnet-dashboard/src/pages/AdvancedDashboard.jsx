import React from 'react';
import { RealTimeProvider } from '../context/RealTimeContext';
import EventStream from '../components/EventStream';
import LiveMetrics from '../components/LiveMetrics';
import AttackAttribution from '../components/AttackAttribution';
import PredictiveAnalytics from '../components/PredictiveAnalytics';
import '../Styles/pages/AdvancedDashboard.css';

const AdvancedDashboard = () => {
    return (
        <RealTimeProvider>
            <div className="advanced-dashboard-container">
                <div className="dashboard-header-premium">
                    <div className="header-badge hud-font">PROTOCOL_ACTIVE</div>
                    <h1 className="dashboard-title glow-text">Neural Operations Center</h1>
                    <p className="dashboard-subtitle text-dim">REAL-TIME THREAT SYCHRONIZATION | AI-DRIVEN PREDICTION</p>
                </div>

                <div className="advanced-dashboard-grid">
                    {/* Top Row: Metrics and Predictive */}
                    <div className="grid-col-1">
                        <LiveMetrics />
                    </div>

                    <div className="grid-col-2">
                        <PredictiveAnalytics />
                    </div>

                    {/* Bottom Row: Event Stream and Attribution */}
                    <div className="grid-col-1">
                        <AttackAttribution />
                    </div>

                    <div className="grid-col-2">
                        <EventStream />
                    </div>
                </div>
            </div>
        </RealTimeProvider>
    );
};

export default AdvancedDashboard;

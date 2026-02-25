import React from "react";
import {
    FaChartLine,
    FaNetworkWired,
    FaServer,
    FaShieldAlt,
    FaExclamationTriangle
} from "react-icons/fa";
import "../Styles/components/PremiumMetricCard.css";

const iconMap = {
    blue: FaChartLine,
    cyan: FaNetworkWired,
    green: FaServer,
    orange: FaShieldAlt,
    red: FaExclamationTriangle,
};

const PremiumMetricCard = ({ title, value, variant = "blue", subtitle = "LIVE TELEMETRY", status = "OPTIMAL", progress = 70 }) => {
    const Icon = iconMap[variant] || FaChartLine;

    return (
        <div className={`premium-metric-card variant-${variant} hud-font`}>
            <div className="hud-corner top-left"></div>
            <div className="hud-corner bottom-right"></div>

            <div className="premium-card-header">
                <div className="premium-icon-box">
                    <Icon />
                </div>
                <div className="header-status-group">
                    <div className="premium-live-tag">
                        <span className="live-dot"></span>
                        LIVE
                    </div>
                    <div className={`premium-status-badge ${variant}`}>
                        {status}
                    </div>
                </div>
            </div>

            <div className="premium-card-body">
                <div className="premium-value-wrapper">
                    <span className="premium-value">
                        {typeof value === 'number' ? value.toLocaleString() : value}
                    </span>
                    <span className="premium-unit">UNIT_01</span>
                </div>

                <div className="premium-progress-container">
                    <div className="premium-progress-track">
                        <div
                            className="premium-progress-fill"
                            style={{ width: `${progress}%` }}
                        >
                            <div className="premium-scan-line"></div>
                        </div>
                    </div>
                </div>

                <div className="premium-info">
                    <h4 className="premium-title">{title}</h4>
                    <p className="premium-subtitle">{subtitle}</p>
                </div>
            </div>

            <div className="premium-card-glow"></div>
        </div>
    );
};

export default PremiumMetricCard;

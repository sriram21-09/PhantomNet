import React from "react";
import {
    RadialBarChart,
    RadialBar,
    PolarAngleAxis,
    ResponsiveContainer,
} from "recharts";
import { FaShieldAlt } from "react-icons/fa";
import "../Styles/components/PremiumMetricCard.css";

const PremiumGaugeCard = ({
    title,
    value,
    variant = "orange",
    subtitle = "SYSTEM ANOMALY",
    status = "ANALYZING",
    progress = 0
}) => {
    const data = [{ name: "Value", value: progress }];

    return (
        <div className={`premium-metric-card variant-${variant} hud-font premium-gauge-card`}>
            <div className="hud-corner top-left"></div>
            <div className="hud-corner bottom-right"></div>

            <div className="premium-card-header">
                <div className="premium-icon-box">
                    <FaShieldAlt />
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
                <div className="premium-gauge-wrapper">
                    <div className="gauge-chart-container">
                        <ResponsiveContainer width="100%" height="100%">
                            <RadialBarChart
                                innerRadius="70%"
                                outerRadius="100%"
                                data={data}
                                startAngle={180}
                                endAngle={0}
                            >
                                <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
                                <RadialBar
                                    minAngle={15}
                                    background={{ fill: 'rgba(148, 163, 184, 0.1)' }}
                                    clockWise
                                    dataKey="value"
                                    cornerRadius={10}
                                    fill={`var(--premium-accent)`}
                                />
                            </RadialBarChart>
                        </ResponsiveContainer>
                    </div>
                    <div className="premium-gauge-value">
                        <span className="premium-value">{value}</span>
                        <span className="premium-unit">RISK_IDX</span>
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

export default PremiumGaugeCard;

import React, { useState } from "react";
import {
    PieChart,
    Pie,
    Cell,
    Tooltip,
    ResponsiveContainer,
    Legend,
    Sector,
} from "recharts";

const protocolData = [
    { name: "SSH", value: 45 },
    { name: "HTTP", value: 30 },
    { name: "SMTP", value: 15 },
    { name: "FTP", value: 10 },
];

const COLORS = ["#3b82f6", "#10b981", "#f59e0b", "#ef4444"];


const ProTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
        const data = payload[0].payload;
        return (
            <div className="pro-tooltip protocol-tooltip-pro">
                <div className="tooltip-header">
                    <span className="tooltip-time">{data.name}</span>
                    <div className="status-dot pulse" style={{ background: payload[0].fill }}></div>
                </div>
                <div className="tooltip-body">
                    <span className="tooltip-label">Distribution</span>
                    <span className="tooltip-value" style={{ color: payload[0].fill }}>{data.value}%</span>
                </div>
            </div>
        );
    }
    return null;
};

const ProtocolChart = () => {
    const [activeIndex, setActiveIndex] = useState(null);
    const totalValue = protocolData.reduce((acc, curr) => acc + curr.value, 0);

    const onPieEnter = (_, index) => {
        setActiveIndex(index);
    };

    const onPieLeave = () => {
        setActiveIndex(null);
    };

    return (
        <div className="protocol-chart-card pro-card">
            <h3 className="panel-title">Protocol Distribution</h3>
            <div className="chart-container" style={{ width: "100%", height: 320, position: "relative" }}>
                <ResponsiveContainer>
                    <PieChart>
                        <Pie
                            activeIndex={activeIndex}
                            activeShape={(props) => {
                                const { cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill } = props;
                                return (
                                    <g>
                                        {/* Outer glow sector */}
                                        <Sector
                                            cx={cx}
                                            cy={cy}
                                            innerRadius={outerRadius + 2}
                                            outerRadius={outerRadius + 4}
                                            startAngle={startAngle}
                                            endAngle={endAngle}
                                            fill={fill}
                                            opacity={0.4}
                                        />
                                        <Sector
                                            cx={cx}
                                            cy={cy}
                                            innerRadius={innerRadius}
                                            outerRadius={outerRadius + 8}
                                            startAngle={startAngle}
                                            endAngle={endAngle}
                                            fill={fill}
                                        />
                                    </g>
                                );
                            }}
                            data={protocolData}
                            cx="50%"
                            cy="55%"
                            innerRadius={75}
                            outerRadius={95}
                            paddingAngle={5}
                            dataKey="value"
                            onMouseEnter={onPieEnter}
                            onMouseLeave={onPieLeave}
                            stroke="none"
                            animationBegin={0}
                            animationDuration={800}
                        >
                            {protocolData.map((entry, index) => (
                                <Cell
                                    key={`cell-${index}`}
                                    fill={COLORS[index % COLORS.length]}
                                    style={{
                                        filter: activeIndex === index ? `drop-shadow(0 0 12px ${COLORS[index]}66)` : 'none',
                                        transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)'
                                    }}
                                />
                            ))}
                        </Pie>
                        {/* Hidden native tooltip to allow center HUD logic to stay simple */}
                        <Tooltip content={<div style={{ display: 'none' }} />} />
                    </PieChart>
                </ResponsiveContainer>

                {/* Central Cyber-HUD Label */}
                <div className={`chart-center-label hud-font ${activeIndex !== null ? 'hud-active' : ''}`}>
                    {activeIndex === null ? (
                        <div className="hud-default">
                            <span className="total-value glow-text">{totalValue}%</span>
                            <span className="total-label text-dim">TRAFFIC</span>
                        </div>
                    ) : (
                        <div className="hud-content">
                            <span className="hud-protocol glow-text" style={{ color: COLORS[activeIndex] }}>
                                {protocolData[activeIndex].name}
                            </span>
                            <span className="hud-value" style={{ color: COLORS[activeIndex] }}>
                                {protocolData[activeIndex].value}%
                            </span>
                            <span className="hud-label text-dim">DISTRIBUTION</span>
                        </div>
                    )}
                </div>
            </div>
            <div className="custom-legend">
                {protocolData.map((entry, index) => (
                    <div
                        key={index}
                        className={`legend-item ${activeIndex === index ? 'active' : ''}`}
                        onMouseEnter={() => onPieEnter(null, index)}
                        onMouseLeave={onPieLeave}
                    >
                        <div className="legend-dot" style={{ backgroundColor: COLORS[index], boxShadow: `0 0 8px ${COLORS[index]}` }}></div>
                        <span className="legend-name">{entry.name}</span>
                        <span className="legend-percent">{entry.value}%</span>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default ProtocolChart;

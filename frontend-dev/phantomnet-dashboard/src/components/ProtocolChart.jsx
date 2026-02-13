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
                                        <Sector
                                            cx={cx}
                                            cy={cy}
                                            innerRadius={innerRadius}
                                            outerRadius={outerRadius + 8}
                                            startAngle={startAngle}
                                            endAngle={endAngle}
                                            fill={fill}
                                        />
                                        <Sector
                                            cx={cx}
                                            cy={cy}
                                            innerRadius={innerRadius}
                                            outerRadius={outerRadius + 12}
                                            startAngle={startAngle}
                                            endAngle={endAngle}
                                            fill={fill}
                                            opacity={0.3}
                                        />
                                    </g>
                                );
                            }}
                            data={protocolData}
                            cx="50%"
                            cy="55%"
                            innerRadius={70}
                            outerRadius={90}
                            paddingAngle={8}
                            dataKey="value"
                            onMouseEnter={onPieEnter}
                            onMouseLeave={onPieLeave}
                            stroke="none"
                        >
                            {protocolData.map((entry, index) => (
                                <Cell
                                    key={`cell-${index}`}
                                    fill={COLORS[index % COLORS.length]}
                                    style={{ filter: activeIndex === index ? 'drop-shadow(0 0 8px rgba(255,255,255,0.2))' : 'none', transition: 'all 0.3s ease' }}
                                />
                            ))}
                        </Pie>
                        <Tooltip content={<ProTooltip />} />
                    </PieChart>
                </ResponsiveContainer>

                {/* Central Total Label */}
                <div className="chart-center-label">
                    <span className="total-value">{totalValue}%</span>
                    <span className="total-label">TRAFFIC</span>
                </div>
            </div>
            <div className="custom-legend">
                {protocolData.map((entry, index) => (
                    <div key={index} className="legend-item">
                        <div className="legend-dot" style={{ backgroundColor: COLORS[index] }}></div>
                        <span className="legend-name">{entry.name}</span>
                        <span className="legend-percent">{entry.value}%</span>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default ProtocolChart;

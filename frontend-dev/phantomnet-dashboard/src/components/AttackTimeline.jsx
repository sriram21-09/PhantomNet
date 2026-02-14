import React, { useContext } from "react";
import { FaChartLine } from "react-icons/fa";
import { ThemeContext } from "../context/ThemeContext";
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    Area,
    AreaChart,
} from "recharts";

const mockTimelineData = [
    { time: "00:00", events: 12 },
    { time: "04:00", events: 19 },
    { time: "08:00", events: 45 },
    { time: "12:00", events: 30 },
    { time: "16:00", events: 65 },
    { time: "20:00", events: 40 },
    { time: "23:59", events: 25 },
];

const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
        return (
            <div className="timeline-tooltip">
                <div className="tooltip-header">
                    <span className="tooltip-time">{label}</span>
                    <div className="status-dot pulse" style={{ background: '#3b82f6' }}></div>
                </div>
                <div className="tooltip-body" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="tooltip-label">Events</span>
                    <span className="tooltip-value">{payload[0].value}</span>
                </div>
            </div>
        );
    }
    return null;
};

const AttackTimeline = () => {
    const { theme } = useContext(ThemeContext);
    const isDark = theme === "dark";

    const gridColor = isDark ? "rgba(255,255,255,0.05)" : "rgba(0,0,0,0.05)";
    const textColor = isDark ? "#64748b" : "#475569";

    return (
        <div className="attack-timeline-card pro-card">
            <div className="card-header">
                <h3 className="panel-title">
                    <div className="title-icon"><FaChartLine /></div>
                    Attack Timeline (24h)
                </h3>
                <div className="timeline-stats">
                    <span className="trend-badge positive">
                        <span className="trend-icon">↑</span>
                        +12% vs yesterday
                    </span>
                </div>
            </div>
            <div className="chart-container" style={{ width: "100%", height: 320 }}>
                <ResponsiveContainer>
                    <AreaChart data={mockTimelineData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                        <defs>
                            <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                            </linearGradient>
                            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                                <feGaussianBlur stdDeviation="4" result="blur" />
                                <feComposite in="SourceGraphic" in2="blur" operator="over" />
                            </filter>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} stroke={gridColor} />
                        <XAxis
                            dataKey="time"
                            stroke={textColor}
                            fontSize={11}
                            tickLine={false}
                            axisLine={false}
                            dy={10}
                        />
                        <YAxis
                            stroke={textColor}
                            fontSize={11}
                            tickLine={false}
                            axisLine={false}
                            dx={-5}
                        />
                        <Tooltip
                            content={<CustomTooltip />}
                            cursor={{
                                stroke: 'rgba(59, 130, 246, 0.4)',
                                strokeWidth: 1,
                                strokeDasharray: '4 4'
                            }}
                        />
                        <Area
                            type="monotone"
                            dataKey="events"
                            stroke="#3b82f6"
                            strokeWidth={3}
                            fillOpacity={1}
                            fill="url(#colorEvents)"
                            activeDot={{
                                r: 6,
                                fill: "#3b82f6",
                                stroke: "#fff",
                                strokeWidth: 2,
                                className: "glowing-active-dot"
                            }}
                            animationDuration={1500}
                        />
                    </AreaChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
};

export default AttackTimeline;

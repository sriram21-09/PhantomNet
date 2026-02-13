import React from "react";
import { FaChartLine } from "react-icons/fa";
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
            <div className="pro-tooltip">
                <div className="tooltip-header">
                    <span className="tooltip-time">{label}</span>
                    <div className="status-dot pulse"></div>
                </div>
                <div className="tooltip-body">
                    <span className="tooltip-label">Events</span>
                    <span className="tooltip-value">{payload[0].value}</span>
                </div>
            </div>
        );
    }
    return null;
};

const AttackTimeline = () => {
    return (
        <div className="attack-timeline-card pro-card">
            <div className="card-header">
                <h3 className="panel-title">
                    <div className="title-icon"><FaChartLine /></div>
                    Attack Timeline (24h)
                </h3>
                <div className="timeline-stats">
                    <span className="trend positive">+12% vs yesterday</span>
                </div>
            </div>
            <div className="chart-container" style={{ width: "100%", height: 320 }}>
                <ResponsiveContainer>
                    <AreaChart data={mockTimelineData}>
                        <defs>
                            <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.6} />
                                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                            </linearGradient>
                            <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                                <feGaussianBlur stdDeviation="3" result="blur" />
                                <feComposite in="SourceGraphic" in2="blur" operator="over" />
                            </filter>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.05)" />
                        <XAxis
                            dataKey="time"
                            stroke="#64748b"
                            fontSize={11}
                            tickLine={false}
                            axisLine={false}
                            dy={10}
                        />
                        <YAxis
                            stroke="#64748b"
                            fontSize={11}
                            tickLine={false}
                            axisLine={false}
                            dx={-5}
                        />
                        <Tooltip content={<CustomTooltip />} cursor={{ stroke: 'rgba(59, 130, 246, 0.2)', strokeWidth: 2 }} />
                        <Area
                            type="monotone"
                            dataKey="events"
                            stroke="#3b82f6"
                            strokeWidth={3}
                            fillOpacity={1}
                            fill="url(#colorEvents)"
                            filter="url(#glow)"
                            animationDuration={2000}
                        />
                    </AreaChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
};

export default AttackTimeline;

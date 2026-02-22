import React, { useEffect, useState } from 'react';
import {
    AreaChart,
    Area,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
} from 'recharts';
import './TrendsChart.css';

const TrendsChart = () => {
    const [data, setData] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchTrends = async () => {
            try {
                const res = await fetch('/api/v1/analytics/trends?days=7');
                if (res.ok) {
                    const trends = await res.json();
                    // Map backend {date, count} to Recharts {name, count}
                    const formatted = trends.map(t => ({
                        name: t.date.split('-').slice(1).join('/'), // MM/DD
                        count: t.count
                    }));
                    setData(formatted);
                }
            } catch (err) {
                console.error("Failed to fetch trends:", err);
            } finally {
                setLoading(false);
            }
        };
        fetchTrends();
    }, []);

    if (loading) return <div className="trends-loading">Loading Analytics...</div>;

    return (
        <div className="trends-chart-card pro-card">
            <div className="card-header hud-font">
                <h3 className="panel-title glow-text">Attack Volumes</h3>
                <span className="live-indicator">LIVE FEED</span>
            </div>
            <div className="chart-container" style={{ width: '100%', height: 260 }}>
                <ResponsiveContainer>
                    <AreaChart data={data}>
                        <defs>
                            <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                            </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#2a2d3e" vertical={false} />
                        <XAxis
                            dataKey="name"
                            stroke="#64748b"
                            fontSize={12}
                            tickLine={false}
                            axisLine={false}
                        />
                        <YAxis
                            stroke="#64748b"
                            fontSize={12}
                            tickLine={false}
                            axisLine={false}
                            tickFormatter={(val) => Math.floor(val)}
                        />
                        <Tooltip
                            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                            itemStyle={{ color: '#3b82f6' }}
                        />
                        <Area
                            type="monotone"
                            dataKey="count"
                            stroke="#3b82f6"
                            strokeWidth={3}
                            fillOpacity={1}
                            fill="url(#colorCount)"
                            animationDuration={1500}
                        />
                    </AreaChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
};

export default TrendsChart;

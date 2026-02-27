import React, { useState, useEffect, useMemo } from 'react';
import {
    AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    ComposedChart, Line, Bar, Legend, RadarChart, PolarGrid, PolarAngleAxis, Radar
} from 'recharts';
import { FaChartLine, FaDownload, FaFileCsv, FaCamera, FaClock, FaShieldAlt, FaBolt } from 'react-icons/fa';
import { toPng } from 'html-to-image';
import '../Styles/pages/AdvancedAnalytics.css';

// --- Sample Data Generators ---
const generateTimelineData = () => {
    return Array.from({ length: 24 }, (_, i) => ({
        time: `${i}:00`,
        incidents: Math.floor(Math.random() * 20) + 5,
        resolved: Math.floor(Math.random() * 15) + 2,
    }));
};

const generateDetectionData = () => {
    return Array.from({ length: 12 }, (_, i) => ({
        month: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][i],
        mttd: Math.floor(Math.random() * 40) + 10, // Minutes
        mttr: Math.floor(Math.random() * 120) + 30, // Minutes
        target: 60
    }));
};

const generateTypeData = [
    { type: 'Brute Force', count: 450, fullMark: 500 },
    { type: 'Malware', count: 280, fullMark: 500 },
    { type: 'DDoS', count: 410, fullMark: 500 },
    { type: 'Phishing', count: 190, fullMark: 500 },
    { type: 'SQLi', count: 120, fullMark: 500 },
];

const AdvancedAnalytics = () => {
    const [timelineData] = useState(generateTimelineData());
    const [performanceData] = useState(generateDetectionData());
    const [isExporting, setIsExporting] = useState(false);

    // --- Export Logic ---
    const exportCSV = () => {
        const headers = ['Month', 'MTTD (min)', 'MTTR (min)', 'Target (min)'];
        const rows = performanceData.map(d => [d.month, d.mttd, d.mttr, d.target]);

        const content = [headers, ...rows].map(e => e.join(",")).join("\n");
        const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement("a");
        const url = URL.createObjectURL(blob);

        link.setAttribute("href", url);
        link.setAttribute("download", `phantomnet_advanced_analytics_${new Date().toISOString().split('T')[0]}.csv`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    const takeSnapshot = async () => {
        const element = document.getElementById('analytics-capture-area');
        if (!element) return;

        setIsExporting(true);
        try {
            const dataUrl = await toPng(element, {
                cacheBust: true,
                backgroundColor: '#020617',
                style: {
                    padding: '20px'
                }
            });
            const link = document.createElement('a');
            link.download = `phantomnet_analytics_snapshot_${Date.now()}.png`;
            link.href = dataUrl;
            link.click();
        } catch (err) {
            console.error('Snapshot failed:', err);
        } finally {
            setIsExporting(false);
        }
    };

    const CustomTooltip = ({ active, payload, label }) => {
        if (active && payload && payload.length) {
            return (
                <div className="custom-chart-tooltip">
                    <p className="tooltip-label hud-font">{label}</p>
                    {payload.map((p, i) => (
                        <p key={i} className="tooltip-value" style={{ color: p.color }}>
                            {p.name.toUpperCase()}: {p.value}
                        </p>
                    ))}
                </div>
            );
        }
        return null;
    };

    return (
        <div className="analytics-wrapper dashboard-wrapper" id="analytics-capture-area">
            <div className="dashboard-header">
                <div className="header-content">
                    <div className="header-title">
                        <div className="dashboard-header-premium">
                            <div className="header-badge hud-font">INTEL_CORE_V.8</div>
                            <h1 className="dashboard-title glow-text">Advanced Analytics</h1>
                            <p className="dashboard-subtitle text-dim">STATISTICAL PERFORMANCE METRICS | HISTORICAL TREND ANALYSIS</p>
                        </div>
                    </div>
                    <div className="header-actions">
                        <div className="export-panel">
                            <button className="export-btn hud-font" onClick={exportCSV}>
                                <FaFileCsv /> CSV DATA
                            </button>
                            <button className="export-btn hud-font" onClick={takeSnapshot} disabled={isExporting}>
                                <FaCamera /> {isExporting ? 'CAPTURING...' : 'SNAPSHOT'}
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            {/* Top Metrics Row */}
            <div className="analytics-metrics-grid">
                <div className="analytics-card-premium pro-card" style={{ '--card-accent': '#3b82f6' }}>
                    <label className="card-label hud-font"><FaClock /> MTTD (MEAN TIME TO DETECT)</label>
                    <div className="card-value">12.4m</div>
                    <div className="card-trend trend-down">▼ 8.2% vs last month</div>
                </div>
                <div className="analytics-card-premium pro-card" style={{ '--card-accent': '#ef4444' }}>
                    <label className="card-label hud-font"><FaBolt /> MTTR (MEAN TIME TO RESPOND)</label>
                    <div className="card-value">42.8m</div>
                    <div className="card-trend trend-down">▼ 15.4% vs last month</div>
                </div>
                <div className="analytics-card-premium pro-card" style={{ '--card-accent': '#10b981' }}>
                    <label className="card-label hud-font"><FaShieldAlt /> ACCURACY RATE</label>
                    <div className="card-value">98.2%</div>
                    <div className="card-trend trend-up">▲ 1.2% precision</div>
                </div>
                <div className="analytics-card-premium pro-card" style={{ '--card-accent': '#f59e0b' }}>
                    <label className="card-label hud-font"><FaChartLine /> TOTAL INCIDENTS</label>
                    <div className="card-value">1,204</div>
                    <div className="card-trend trend-up">▲ 4% volume growth</div>
                </div>
            </div>

            {/* Main Charts Row */}
            <div className="analytics-charts-grid">
                <div className="chart-card pro-card chart-container-large">
                    <div className="chart-header">
                        <h3 className="chart-title hud-font">Incident Frequency Timeline (24H)</h3>
                    </div>
                    <ResponsiveContainer width="100%" height={300}>
                        <AreaChart data={timelineData}>
                            <defs>
                                <linearGradient id="colorInc" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                            <XAxis dataKey="time" stroke="#64748b" fontSize={10} axisLine={false} tickLine={false} />
                            <YAxis stroke="#64748b" fontSize={10} axisLine={false} tickLine={false} />
                            <Tooltip content={<CustomTooltip />} />
                            <Area type="monotone" dataKey="incidents" stroke="#3b82f6" fillOpacity={1} fill="url(#colorInc)" strokeWidth={2} />
                            <Area type="monotone" dataKey="resolved" stroke="#10b981" fillOpacity={0} strokeWidth={2} strokeDasharray="5 5" />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>

                <div className="chart-card pro-card">
                    <div className="chart-header">
                        <h3 className="chart-title hud-font">MTTD vs MTTR Performance</h3>
                    </div>
                    <ResponsiveContainer width="100%" height={300}>
                        <ComposedChart data={performanceData}>
                            <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                            <XAxis dataKey="month" stroke="#64748b" fontSize={10} />
                            <YAxis stroke="#64748b" fontSize={10} />
                            <Tooltip content={<CustomTooltip />} />
                            <Legend wrapperStyle={{ fontSize: '10px', paddingTop: '10px' }} />
                            <Bar dataKey="mttd" fill="#3b82f6" radius={[4, 4, 0, 0]} name="MTTD (Min)" />
                            <Line type="monotone" dataKey="mttr" stroke="#ef4444" strokeWidth={2} dot={{ r: 4 }} name="MTTR (Min)" />
                            <Line type="step" dataKey="target" stroke="#64748b" strokeDasharray="5 5" dot={false} name="Target" />
                        </ComposedChart>
                    </ResponsiveContainer>
                </div>

                <div className="chart-card pro-card">
                    <div className="chart-header">
                        <h3 className="chart-title hud-font">Threat Vector Distribution</h3>
                    </div>
                    <ResponsiveContainer width="100%" height={300}>
                        <RadarChart cx="50%" cy="50%" outerRadius="80%" data={generateTypeData}>
                            <PolarGrid stroke="rgba(255,255,255,0.1)" />
                            <PolarAngleAxis dataKey="type" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                            <Radar
                                name="Volume"
                                dataKey="count"
                                stroke="#3b82f6"
                                fill="#3b82f6"
                                fillOpacity={0.4}
                            />
                        </RadarChart>
                    </ResponsiveContainer>
                </div>
            </div>
        </div>
    );
};

export default AdvancedAnalytics;

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useRealTime } from '../context/RealTimeContext';
import { PieChart, Pie, Cell, ResponsiveContainer, LineChart, Line, YAxis, Tooltip } from 'recharts';
import { Activity, Shield, Users, Server, Cpu, Database, Zap, BarChart3 } from 'lucide-react';
import './LiveMetrics.css';

const CountUp = ({ end, duration = 800, decimals = 0 }) => {
    const [count, setCount] = useState(0);

    useEffect(() => {
        let start = 0;
        const increment = end / (duration / 16);
        const timer = setInterval(() => {
            start += increment;
            if (start >= end) {
                setCount(end);
                clearInterval(timer);
            } else {
                setCount(decimals > 0 ? parseFloat(start.toFixed(decimals)) : Math.floor(start));
            }
        }, 16);
        return () => clearInterval(timer);
    }, [end, duration, decimals]);

    return <span>{decimals > 0 ? count.toFixed(decimals) : count.toLocaleString()}</span>;
};

const TrendArrow = ({ current, previous }) => {
    if (!previous || current === previous) return <span className="trend-stable">━</span>;
    if (current > previous) return <span className="trend-up">▲</span>;
    return <span className="trend-down">▼</span>;
};

const LiveMetrics = () => {
    const { metrics } = useRealTime();
    const [history, setHistory] = useState([]);
    const [epmHistory, setEpmHistory] = useState([]);
    const [prevMetrics, setPrevMetrics] = useState(null);

    useEffect(() => {
        if (metrics) {
            setPrevMetrics(prev => prev ? prev : metrics);
            setHistory(prev => [...prev.slice(-29), { val: metrics.totalEvents || 0, ts: Date.now() }]);
            setEpmHistory(prev => [...prev.slice(-29), { val: metrics.events_per_minute || 0, ts: Date.now() }]);
            // Update prev every 10s
            const timer = setTimeout(() => setPrevMetrics(metrics), 10000);
            return () => clearTimeout(timer);
        }
    }, [metrics]);

    const threatData = useMemo(() => {
        if (!metrics) return [];
        
        // Use real distribution from backend if available
        if (metrics.distribution) {
            return [
                { name: 'Critical', value: metrics.distribution.critical || 0, color: '#ff0055' },
                { name: 'Suspicious', value: metrics.distribution.suspicious || 0, color: '#f77f00' },
                { name: 'Benign', value: metrics.distribution.benign || 0, color: '#00ff41' },
            ];
        }

        // Fallback (only if old backend or missing data)
        const critical = metrics.criticalAlerts || 0;
        const total = metrics.totalEvents || 0;
        const suspicious = Math.max(0, Math.floor(total * 0.1)); // Reduced fallback ratio
        const benign = Math.max(0, total - critical - suspicious);
        return [
            { name: 'Critical', value: critical, color: '#ff0055' },
            { name: 'Suspicious', value: suspicious, color: '#f77f00' },
            { name: 'Benign', value: benign, color: '#00ff41' },
        ];
    }, [metrics]);

    if (!metrics) return (
        <div className="metrics-loading">
            <div className="loading-pulse"></div>
            <span>Initializing Neural Link...</span>
        </div>
    );

    return (
        <div className="live-metrics-grid">
            {/* Top Stats Row */}
            <div className="metrics-top-row">
                <div className="metric-card-mini glow-card">
                    <div className="card-icon icon-cyan"><Activity size={20} /></div>
                    <div className="card-info">
                        <label>EVENTS / MIN</label>
                        <div className="value"><CountUp end={metrics.events_per_minute || 0} decimals={1} /></div>
                    </div>
                    <div className="sparkline">
                        <ResponsiveContainer width="100%" height={40}>
                            <LineChart data={epmHistory}>
                                <Line type="monotone" dataKey="val" stroke="#4cc9f0" strokeWidth={2} dot={false} isAnimationActive={false} />
                                <YAxis hide domain={['dataMin', 'dataMax']} />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="metric-card-mini glow-card">
                    <div className="card-icon icon-cyan"><BarChart3 size={20} /></div>
                    <div className="card-info">
                        <label>TOTAL EVENTS</label>
                        <div className="value">
                            <CountUp end={metrics.totalEvents || 0} />
                            <TrendArrow current={metrics.totalEvents} previous={prevMetrics?.totalEvents} />
                        </div>
                    </div>
                    <div className="sparkline">
                        <ResponsiveContainer width="100%" height={40}>
                            <LineChart data={history}>
                                <Line type="monotone" dataKey="val" stroke="#4cc9f0" strokeWidth={2} dot={false} isAnimationActive={false} />
                                <YAxis hide domain={['dataMin', 'dataMax']} />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="metric-card-mini glow-card">
                    <div className="card-icon icon-orange"><Users size={20} /></div>
                    <div className="card-info">
                        <label>ACTIVE ATTACKERS</label>
                        <div className="value">
                            <CountUp end={metrics.uniqueIPs || 0} />
                            <TrendArrow current={metrics.uniqueIPs} previous={prevMetrics?.uniqueIPs} />
                        </div>
                    </div>
                </div>

                <div className="metric-card-mini glow-card">
                    <div className="card-icon icon-green"><Shield size={20} /></div>
                    <div className="card-info">
                        <label>AVG THREAT SCORE</label>
                        <div className="value">{metrics.avgThreatScore || 0}%</div>
                    </div>
                </div>
            </div>

            {/* Charts Section */}
            <div className="metrics-middle-row">
                <div className="distribution-chart glass-panel">
                    <h4><Zap size={14} /> THREAT DISTRIBUTION</h4>
                    <div className="chart-container">
                        <ResponsiveContainer width="100%" height={160}>
                            <PieChart>
                                <Pie
                                    data={threatData}
                                    innerRadius={50}
                                    outerRadius={70}
                                    paddingAngle={5}
                                    dataKey="value"
                                    isAnimationActive={false}
                                >
                                    {threatData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip
                                    contentStyle={{ background: 'rgba(10,10,10,0.9)', border: '1px solid #333', borderRadius: '6px', fontSize: '0.75rem' }}
                                    itemStyle={{ color: '#e0e0e0' }}
                                />
                            </PieChart>
                        </ResponsiveContainer>
                        <div className="chart-legend">
                            {threatData.map(item => (
                                <div key={item.name} className="legend-item">
                                    <span className="legend-dot" style={{ backgroundColor: item.color }}></span>
                                    <span className="legend-name">{item.name}</span>
                                    <span className="legend-value">{item.value}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="honeypot-status-summary glass-panel">
                    <h4><Server size={14} /> HONEYPOT NODES</h4>
                    <div className="node-list">
                        {(metrics.honeypots || []).map(hp => (
                            <div key={hp.name} className={`node-item ${hp.status === 'active' ? 'node-active' : 'node-inactive'}`}>
                                <span className={`status-dot ${hp.status === 'active' ? 'online' : 'offline'}`}></span>
                                <span className="node-name">{hp.name}</span>
                                <span className="node-port">:{hp.port}</span>
                                <span className={`node-status-label ${hp.status === 'active' ? 'label-online' : 'label-offline'}`}>
                                    {hp.status === 'active' ? 'ONLINE' : 'OFFLINE'}
                                </span>
                            </div>
                        ))}
                        {(!metrics.honeypots || metrics.honeypots.length === 0) && (
                            <div className="node-item node-inactive">
                                <span className="status-dot offline"></span>
                                <span className="node-name">No honeypots detected</span>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* System Health and ML Status */}
            <div className="metrics-bottom-row">
                <div className="system-health glass-panel">
                    <h4><Cpu size={14} /> SYSTEM HEALTH</h4>
                    <div className="health-bars">
                        {[
                            { icon: <Cpu size={14} />, label: 'CPU', value: metrics.system_health?.cpu || 0, threshold: 80 },
                            { icon: <Database size={14} />, label: 'MEMORY', value: metrics.system_health?.memory || 0, threshold: 80 },
                            { icon: <Server size={14} />, label: 'DISK', value: metrics.system_health?.disk || 0, threshold: 90 },
                        ].map(item => (
                            <div className="health-item" key={item.label}>
                                <div className="label">{item.icon} {item.label}</div>
                                <div className="bar-container">
                                    <div
                                        className="bar"
                                        style={{
                                            width: `${item.value}%`,
                                            background: item.value > item.threshold
                                                ? 'linear-gradient(90deg, #f77f00, #ff0055)'
                                                : 'linear-gradient(90deg, #4cc9f0, #00ff41)',
                                        }}
                                    ></div>
                                    <span className={item.value > item.threshold ? 'value-warn' : ''}>{item.value}%</span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="ml-status-panel glass-panel">
                    <h4><Zap size={14} /> ML ENGINE STATUS</h4>
                    <div className="ml-grid">
                        <div className="ml-item">
                            <label>INFERENCE</label>
                            <span className="ml-value">{metrics.ml_status?.inference_time || 'N/A'}</span>
                        </div>
                        <div className="ml-item">
                            <label>QUEUE</label>
                            <span className="ml-value">{metrics.ml_status?.queue_depth ?? 'N/A'}</span>
                        </div>
                        <div className="ml-item">
                            <label>STATUS</label>
                            <span className={`ml-value ${metrics.ml_status?.status === 'online' ? 'status-online' : 'status-offline'}`}>
                                {(metrics.ml_status?.status || 'offline').toUpperCase()}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default LiveMetrics;

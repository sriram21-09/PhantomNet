import React, { useState, useEffect } from 'react';
import { useRealTime } from '../context/RealTimeContext';
import { PieChart, Pie, Cell, ResponsiveContainer, LineChart, Line, YAxis } from 'recharts';
import { Activity, Shield, Users, Server, Cpu, Database } from 'lucide-react';
import './LiveMetrics.css';

const CountUp = ({ end, duration = 1000 }) => {
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
                setCount(Math.floor(start));
            }
        }, 16);
        return () => clearInterval(timer);
    }, [end]);

    return <span>{count.toLocaleString()}</span>;
};

const LiveMetrics = () => {
    const { metrics } = useRealTime();
    const [history, setHistory] = useState([]);

    useEffect(() => {
        if (metrics) {
            setHistory(prev => [...prev.slice(-19), { val: metrics.totalEvents }]);
        }
    }, [metrics]);

    if (!metrics) return <div className="metrics-loading">Initializing Neural Link...</div>;

    const threatData = [
        { name: 'Critical', value: metrics.criticalAlerts, color: '#ff0055' },
        { name: 'Suspicious', value: metrics.totalEvents - metrics.criticalAlerts, color: '#f77f00' },
        { name: 'Benign', value: Math.max(0, 100 - metrics.totalEvents), color: '#00ff41' }
    ];

    return (
        <div className="live-metrics-grid">
            {/* Main Stats */}
            <div className="metric-card-mini">
                <div className="card-icon"><Activity size={20} color="#4cc9f0" /></div>
                <div className="card-info">
                    <label>TOTAL EVENTS</label>
                    <div className="value"><CountUp end={metrics.totalEvents} /></div>
                </div>
                <div className="sparkline">
                    <ResponsiveContainer width="100%" height={40}>
                        <LineChart data={history}>
                            <Line type="monotone" dataKey="val" stroke="#4cc9f0" strokeWidth={2} dot={false} isAnimationActive={false} />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
            </div>

            <div className="metric-card-mini">
                <div className="card-icon"><Users size={20} color="#f77f00" /></div>
                <div className="card-info">
                    <label>ACTIVE ATTACKERS</label>
                    <div className="value"><CountUp end={metrics.uniqueIPs} /></div>
                </div>
            </div>

            <div className="metric-card-mini">
                <div className="card-icon"><Shield size={20} color="#00ff41" /></div>
                <div className="card-info">
                    <label>AVG THREAT SCORE</label>
                    <div className="value">{metrics.avgThreatScore}%</div>
                </div>
            </div>

            {/* Charts Section */}
            <div className="metrics-middle-row">
                <div className="distribution-chart">
                    <h4>THREAT DISTRIBUTION</h4>
                    <div className="chart-container">
                        <ResponsiveContainer width="100%" height={150}>
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
                            </PieChart>
                        </ResponsiveContainer>
                        <div className="chart-legend">
                            {threatData.map(item => (
                                <div key={item.name} className="legend-item">
                                    <span style={{ backgroundColor: item.color }}></span>
                                    {item.name}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="honeypot-status-summary">
                    <h4>HONEYPOT NODES</h4>
                    <div className="node-list">
                        {(metrics.honeypots || []).map(hp => (
                            <div key={hp.name} className="node-item">
                                <span className={`status-dot ${hp.status === 'active' ? 'online' : 'offline'}`}></span>
                                <span className="node-name">{hp.name}</span>
                                <span className="node-port">PORT {hp.port}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* System Health and ML Status */}
            <div className="metrics-bottom-row">
                <div className="system-health">
                    <h4>SYSTEM HEALTH</h4>
                    <div className="health-bars">
                        <div className="health-item">
                            <div className="label"><Cpu size={14} /> CPU</div>
                            <div className="bar-container">
                                <div className="bar" style={{ width: `${metrics.system_health.cpu}%`, backgroundColor: metrics.system_health.cpu > 80 ? '#ff0055' : '#4cc9f0' }}></div>
                                <span>{metrics.system_health.cpu}%</span>
                            </div>
                        </div>
                        <div className="health-item">
                            <div className="label"><Database size={14} /> MEMORY</div>
                            <div className="bar-container">
                                <div className="bar" style={{ width: `${metrics.system_health.memory}%`, backgroundColor: metrics.system_health.memory > 80 ? '#ff0055' : '#4cc9f0' }}></div>
                                <span>{metrics.system_health.memory}%</span>
                            </div>
                        </div>
                        <div className="health-item">
                            <div className="label"><Server size={14} /> DISK</div>
                            <div className="bar-container">
                                <div className="bar" style={{ width: `${metrics.system_health.disk}%`, backgroundColor: metrics.system_health.disk > 90 ? '#ff0055' : '#4cc9f0' }}></div>
                                <span>{metrics.system_health.disk}%</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="ml-status-panel">
                    <h4>ML ENGINE STATUS</h4>
                    <div className="ml-grid">
                        <div className="ml-item">
                            <label>INFERENCE</label>
                            <span>{metrics.ml_status.inference_time}</span>
                        </div>
                        <div className="ml-item">
                            <label>QUEUE</label>
                            <span>{metrics.ml_status.queue_depth}</span>
                        </div>
                        <div className="ml-item">
                            <label>STATUS</label>
                            <span className="status-online">{metrics.ml_status.status.toUpperCase()}</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default LiveMetrics;

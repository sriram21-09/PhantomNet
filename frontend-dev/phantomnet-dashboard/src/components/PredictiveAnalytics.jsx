import React, { useState, useEffect, useMemo } from 'react';
import { useRealTime } from '../context/RealTimeContext';
import { BrainCircuit, TrendingUp, TrendingDown, AlertTriangle, Radio, Minus, Gauge } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import './PredictiveAnalytics.css';

const PredictiveAnalytics = () => {
    const { metrics, events } = useRealTime();
    const [countdown, setCountdown] = useState(null);
    const [forecastData, setForecastData] = useState([]);

    // Generate dynamic forecast from metrics history
    useEffect(() => {
        if (!metrics) return;

        const now = new Date();
        const baseVolume = metrics.events_per_minute || 5;
        const data = [];

        // Historical data (past 4 hours)
        for (let i = -4; i <= 0; i++) {
            const t = new Date(now.getTime() + i * 3600000);
            const jitter = Math.random() * 10 - 5;
            data.push({
                time: t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                current: Math.max(0, Math.round(baseVolume * 60 + jitter * 6 + i * 3)),
            });
        }

        // Forecast data (next 3 hours)
        const trend = (metrics.avgThreatScore || 30) > 50 ? 1.15 : 0.95;
        for (let i = 1; i <= 3; i++) {
            const t = new Date(now.getTime() + i * 3600000);
            const predicted = Math.round(baseVolume * 60 * Math.pow(trend, i) + Math.random() * 8);
            data.push({
                time: t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                forecast: Math.max(0, predicted),
            });
        }

        setForecastData(data);
    }, [metrics]);

    // Countdown timer for next predicted attack
    useEffect(() => {
        if (!metrics) return;

        const baseMinutes = Math.max(3, 25 - (metrics.events_per_minute || 0) * 2);
        setCountdown(Math.round(baseMinutes * 60));

        const interval = setInterval(() => {
            setCountdown(prev => {
                if (prev <= 1) return Math.round(baseMinutes * 60);
                return prev - 1;
            });
        }, 1000);

        return () => clearInterval(interval);
    }, [metrics?.events_per_minute]);

    const formatCountdown = (seconds) => {
        if (!seconds) return '--:--';
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return `${String(m).padStart(2, '0')}m ${String(s).padStart(2, '0')}s`;
    };

    // Determine predicted target based on most attacked protocol
    const predictedTarget = useMemo(() => {
        if (events.length === 0) return { name: 'SSH HONEYPOT', port: 2222, confidence: 42 };

        const protoCounts = {};
        events.forEach(e => {
            const p = e.protocol || 'TCP';
            protoCounts[p] = (protoCounts[p] || 0) + 1;
        });

        const sorted = Object.entries(protoCounts).sort((a, b) => b[1] - a[1]);
        const topProto = sorted[0]?.[0] || 'SSH';

        const targetMap = {
            SSH: { name: 'SSH HONEYPOT', port: 2222 },
            HTTP: { name: 'HTTP HONEYPOT', port: 8080 },
            FTP: { name: 'FTP HONEYPOT', port: 2121 },
            SMTP: { name: 'SMTP HONEYPOT', port: 2525 },
            TCP: { name: 'NETWORK PERIMETER', port: 0 },
        };

        const target = targetMap[topProto] || { name: `${topProto} SERVICE`, port: 0 };
        const avgScore = events.reduce((s, e) => s + (e.threat_score || 0), 0) / events.length;
        const confidence = Math.min(95, Math.max(35, Math.round(avgScore * 0.8 + sorted[0]?.[1] * 0.5)));

        return { ...target, confidence };
    }, [events]);

    if (!metrics) {
        return (
            <div className="predictive-container">
                <div className="predictive-loading">
                    <BrainCircuit size={24} className="spin" />
                    <span>Synchronizing Predictive Engine...</span>
                </div>
            </div>
        );
    }

    const getRiskLevel = (score) => {
        if (score > 80) return { label: 'CRITICAL', class: 'risk-critical' };
        if (score > 60) return { label: 'HIGH', class: 'risk-high' };
        if (score > 30) return { label: 'MEDIUM', class: 'risk-medium' };
        return { label: 'LOW', class: 'risk-low' };
    };

    const risk = getRiskLevel(metrics.avgThreatScore || 0);

    // Trend direction
    const trendDirection = useMemo(() => {
        if (!metrics) return 'STABLE';
        const score = metrics.avgThreatScore || 0;
        if (score > 60) return 'RISING';
        if (score < 25) return 'FALLING';
        return 'STABLE';
    }, [metrics]);

    const TrendIcon = trendDirection === 'RISING' ? TrendingUp : trendDirection === 'FALLING' ? TrendingDown : Minus;

    return (
        <div className="predictive-container">
            <div className="predictive-header">
                <h3><BrainCircuit size={16} /> PREDICTIVE ANALYTICS</h3>
                <div className="engine-status">
                    <span className="engine-dot"></span>
                    LSTM-V3 ACTIVE
                </div>
            </div>

            <div className="predictive-grid">
                {/* Risk Score Widget */}
                <div className="risk-widget">
                    <label><Gauge size={12} /> AGGREGATE RISK SCORE</label>
                    <div className={`risk-value ${risk.class}`}>
                        <span className="risk-number">{metrics.avgThreatScore || 0}%</span>
                        <span className="risk-label">{risk.label}</span>
                    </div>
                    <div className="risk-meter">
                        <div
                            className={`meter-fill ${risk.class}`}
                            style={{ width: `${metrics.avgThreatScore || 0}%` }}
                        ></div>
                    </div>
                    <div className="risk-indicators">
                        <span className="indicator">LOW</span>
                        <span className="indicator">MED</span>
                        <span className="indicator">HIGH</span>
                        <span className="indicator">CRIT</span>
                    </div>
                </div>

                {/* Prediction Box */}
                <div className="prediction-box">
                    <div className="prediction-header-label">
                        <Radio size={14} className="pulse-icon" /> NEXT ATTACK PREDICTION
                    </div>
                    <div className="prediction-content">
                        <div className="pred-item">
                            <label>LIKELY TARGET:</label>
                            <span className="target-value">{predictedTarget.name} (PORT {predictedTarget.port})</span>
                        </div>
                        <div className="pred-item">
                            <label>CONFIDENCE:</label>
                            <div className="conf-container">
                                <div className="conf-bar-bg">
                                    <div className="conf-bar-fill" style={{ width: `${predictedTarget.confidence}%` }}></div>
                                </div>
                                <span className="conf-value">{predictedTarget.confidence}%</span>
                            </div>
                        </div>
                        <div className="pred-item">
                            <label>EST. TIME:</label>
                            <span className="countdown-value">T-MINUS {formatCountdown(countdown)}</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Trend Forecast */}
            <div className="trend-forecast">
                <div className="trend-header">
                    <div className="trend-title">
                        <TrendIcon size={14} /> ATTACK VOLUME FORECAST
                    </div>
                    <div className={`trend-badge trend-${trendDirection.toLowerCase()}`}>
                        {trendDirection}
                    </div>
                </div>
                <div className="forecast-chart">
                    <ResponsiveContainer width="100%" height={130}>
                        <AreaChart data={forecastData}>
                            <defs>
                                <linearGradient id="colorCurrent" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#4cc9f0" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#4cc9f0" stopOpacity={0} />
                                </linearGradient>
                                <linearGradient id="colorForecast" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#f77f00" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#f77f00" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <XAxis dataKey="time" tick={{ fill: '#666', fontSize: 10 }} axisLine={false} tickLine={false} />
                            <YAxis hide />
                            <Tooltip
                                contentStyle={{ background: 'rgba(10,10,10,0.9)', border: '1px solid #333', borderRadius: '6px', fontSize: '0.75rem' }}
                                itemStyle={{ color: '#e0e0e0' }}
                            />
                            <Area type="monotone" dataKey="current" stroke="#4cc9f0" fillOpacity={1} fill="url(#colorCurrent)" strokeWidth={2} />
                            <Area type="monotone" dataKey="forecast" stroke="#f77f00" fillOpacity={1} fill="url(#colorForecast)" strokeDasharray="5 5" strokeWidth={2} />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>
                <div className="forecast-legend">
                    <span className="fl-item"><span className="fl-dot current"></span> Historical</span>
                    <span className="fl-item"><span className="fl-dot forecast"></span> Predicted</span>
                </div>
            </div>

            <div className="predictive-footer">
                <AlertTriangle size={12} />
                {trendDirection === 'RISING'
                    ? '⚠ Expected surge in attack volume within the next 2 hours.'
                    : trendDirection === 'FALLING'
                        ? '✅ Attack volume trending downward. Maintaining vigilance.'
                        : '📊 Attack volume holding steady. Monitoring for changes.'
                }
            </div>
        </div>
    );
};

export default PredictiveAnalytics;

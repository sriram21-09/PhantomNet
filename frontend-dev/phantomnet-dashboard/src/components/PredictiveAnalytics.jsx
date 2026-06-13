import React, { useState, useEffect } from 'react';
import { BrainCircuit, TrendingUp, TrendingDown, TriangleAlert, Radio, Minus, Gauge } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import './PredictiveAnalytics.css';

const PredictiveAnalytics = () => {
    const [loading, setLoading] = useState(true);
    const [countdown, setCountdown] = useState(null);
    const [forecastData, setForecastData] = useState([]);
    const [riskScore, setRiskScore] = useState(0);
    const [riskLevel, setRiskLevel] = useState('LOW');
    const [predictedTarget, setPredictedTarget] = useState({
        target: 'SSH HONEYPOT (PORT 2222)',
        confidence: 42
    });
    const [trendDirection, setTrendDirection] = useState('STABLE');

    const fetchPredictiveData = async () => {
        try {
            const [forecastRes, riskRes, nextRes] = await Promise.all([
                fetch('/api/v1/predictive/forecast'),
                fetch('/api/v1/predictive/risk-score'),
                fetch('/api/v1/predictive/next-attack')
            ]);

            if (!forecastRes.ok || !riskRes.ok || !nextRes.ok) {
                throw new Error('Failed to fetch predictive data');
            }

            const forecast = await forecastRes.json();
            const risk = await riskRes.json();
            const nextAttack = await nextRes.json();

            const combined = [
                ...(forecast.historical || []).map(h => ({ time: h.time, current: h.current })),
                ...(forecast.forecast || []).map(f => ({ time: f.time, forecast: f.predicted }))
            ];
            
            setForecastData(combined);
            setRiskScore(risk.risk_score || 0);
            setRiskLevel(risk.risk_level || 'LOW');
            setPredictedTarget({
                target: nextAttack.target || 'SSH HONEYPOT (PORT 2222)',
                confidence: nextAttack.confidence || 42
            });
            setTrendDirection(forecast.trend || 'STABLE');
            
            setCountdown(prev => {
                if (prev === null || prev <= 0) {
                    return Math.round((nextAttack.estimated_minutes || 25) * 60);
                }
                return prev;
            });
            setLoading(false);
        } catch (err) {
            console.error('Error fetching predictive data:', err);
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchPredictiveData();
        const interval = setInterval(fetchPredictiveData, 10000);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        const timer = setInterval(() => {
            setCountdown(prev => {
                if (prev === null) return null;
                if (prev <= 1) {
                    fetchPredictiveData();
                    return 0;
                }
                return prev - 1;
            });
        }, 1000);
        return () => clearInterval(timer);
    }, []);

    const formatCountdown = (seconds) => {
        if (!seconds) return '--:--';
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return `${String(m).padStart(2, '0')}m ${String(s).padStart(2, '0')}s`;
    };

    if (loading && forecastData.length === 0) {
        return (
            <div className="predictive-container">
                <div className="predictive-loading">
                    <BrainCircuit size={24} className="spin" />
                    <span>Synchronizing Predictive Engine...</span>
                </div>
            </div>
        );
    }

    const getRiskClass = (level) => {
        const lower = String(level).toLowerCase();
        if (lower === 'critical') return 'risk-critical';
        if (lower === 'high') return 'risk-high';
        if (lower === 'medium') return 'risk-medium';
        return 'risk-low';
    };

    const riskClass = getRiskClass(riskLevel);
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
                    <div className={`risk-value ${riskClass}`}>
                        <span className="risk-number">{riskScore}%</span>
                        <span className="risk-label">{riskLevel}</span>
                    </div>
                    <div className="risk-meter">
                        <div
                            className={`meter-fill ${riskClass}`}
                            style={{ width: `${riskScore}%` }}
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
                            <span className="target-value">{predictedTarget.target}</span>
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
                <TriangleAlert size={12} />
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

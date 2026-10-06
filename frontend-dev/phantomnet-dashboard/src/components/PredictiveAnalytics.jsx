import React, { useState, useEffect } from 'react';
import { BrainCircuit, TrendingUp, TrendingDown, TriangleAlert, ShieldAlert, Radio, Minus, Gauge, RotateCcw } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import './PredictiveAnalytics.css';

const PredictiveAnalytics = () => {
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [errorCode, setErrorCode] = useState(null);
    const [countdown, setCountdown] = useState(null);
    const [forecastData, setForecastData] = useState([]);
    const [riskScore, setRiskScore] = useState(null);
    const [riskLevel, setRiskLevel] = useState('LOW');
    const [modelName, setModelName] = useState('Statistical Protocol Frequency Analysis');
    const [predictedTarget, setPredictedTarget] = useState({
        target: 'N/A',
        confidence: null,
        has_data: false
    });
    const [trendDirection, setTrendDirection] = useState('STABLE');

    const fetchPredictiveData = async () => {
        try {
            const [forecastRes, riskRes, nextRes] = await Promise.all([
                fetch('/api/v1/predictive/forecast', { credentials: 'include' }),
                fetch('/api/v1/predictive/risk-score', { credentials: 'include' }),
                fetch('/api/v1/predictive/next-attack', { credentials: 'include' })
            ]);

            if (forecastRes.status === 401 || riskRes.status === 401 || nextRes.status === 401) {
                setErrorCode(401);
                throw new Error('Authentication required to access predictive telemetry');
            }
            if (forecastRes.status === 403 || riskRes.status === 403 || nextRes.status === 403) {
                setErrorCode(403);
                throw new Error('Access forbidden to predictive telemetry');
            }
            if (!forecastRes.ok || !riskRes.ok || !nextRes.ok) {
                setErrorCode(forecastRes.status || 500);
                throw new Error(`Unable to load predictive analytics (status: ${forecastRes.status})`);
            }

            const forecast = await forecastRes.json();
            const risk = await riskRes.json();
            const nextAttack = await nextRes.json();

            const combined = [
                ...(forecast.historical || []).map(h => ({ time: h.time, current: h.current })),
                ...(forecast.forecast || []).map(f => ({ time: f.time, forecast: f.predicted }))
            ];

            setForecastData(combined);
            setRiskScore(typeof risk.risk_score === 'number' ? risk.risk_score : null);
            setRiskLevel(risk.risk_level || 'LOW');
            setModelName(forecast.model || 'Statistical Protocol Frequency Analysis');

            const hasValidData = nextAttack.has_data !== false && nextAttack.target && nextAttack.target !== 'Insufficient data';
            setPredictedTarget({
                target: hasValidData ? nextAttack.target : 'Insufficient data',
                confidence: hasValidData && typeof nextAttack.confidence === 'number' ? nextAttack.confidence : null,
                has_data: hasValidData
            });
            setTrendDirection(forecast.trend || 'STABLE');

            if (hasValidData && typeof nextAttack.estimated_minutes === 'number') {
                setCountdown(Math.round(nextAttack.estimated_minutes * 60));
            } else {
                setCountdown(null);
            }
            setError(null);
            setErrorCode(null);
            setLoading(false);
        } catch (err) {
            setError(err.message || 'Unable to load predictive analytics');
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchPredictiveData();
        const interval = setInterval(fetchPredictiveData, 15000);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        if (countdown === null) return;
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
    }, [countdown]);

    const formatCountdown = (seconds) => {
        if (!seconds || seconds <= 0) return 'N/A (Awaiting pattern)';
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return `T-MINUS ${String(m).padStart(2, '0')}m ${String(s).padStart(2, '0')}s`;
    };

    const getRiskClass = (level) => {
        const lower = String(level).toLowerCase();
        if (lower === 'critical') return 'risk-critical';
        if (lower === 'high') return 'risk-high';
        if (lower === 'medium') return 'risk-medium';
        return 'risk-low';
    };

    const riskClass = getRiskClass(riskLevel);
    const TrendIcon = trendDirection === 'RISING' ? TrendingUp : trendDirection === 'FALLING' ? TrendingDown : Minus;

    if (loading && forecastData.length === 0 && !error) {
        return (
            <div className="predictive-container">
                <div className="predictive-loading">
                    <BrainCircuit size={24} className="spin" />
                    <span>Synchronizing Predictive Telemetry...</span>
                </div>
            </div>
        );
    }

    if (error && forecastData.length === 0) {
        return (
            <div className="predictive-container">
                <div className="predictive-header">
                    <h3><BrainCircuit size={16} /> PREDICTIVE ANALYTICS</h3>
                </div>
                <div className="predictive-error-state">
                    <ShieldAlert size={28} className="error-icon" />
                    <div className="error-title">
                        {errorCode === 401 ? 'Authentication Required' : 'Telemetry Unavailable'}
                    </div>
                    <div className="error-detail">{error}</div>
                    <button className="retry-btn" onClick={fetchPredictiveData}>
                        <RotateCcw size={14} /> Retry Connection
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="predictive-container">
            <div className="predictive-header">
                <h3><BrainCircuit size={16} /> PREDICTIVE ANALYTICS</h3>
                <div className="engine-status" title={`Algorithm: ${modelName}`}>
                    <span className="engine-dot"></span>
                    STATISTICAL FORECAST
                </div>
            </div>

            <div className="predictive-grid">
                {/* Risk Score Widget */}
                <div className="risk-widget">
                    <label><Gauge size={12} /> AGGREGATE RISK SCORE</label>
                    <div className={`risk-value ${riskClass}`}>
                        <span className="risk-number">
                            {riskScore !== null ? `${riskScore}%` : 'N/A'}
                        </span>
                        <span className="risk-label">{riskLevel}</span>
                    </div>
                    <div className="risk-meter">
                        <div
                            className={`meter-fill ${riskClass}`}
                            style={{ width: `${riskScore !== null ? riskScore : 0}%` }}
                        ></div>
                    </div>
                    <div className="risk-indicators">
                        <span className="indicator">LOW (&lt;40%)</span>
                        <span className="indicator">MED (&gt;=40%)</span>
                        <span className="indicator">HIGH (&gt;=60%)</span>
                        <span className="indicator">CRIT (&gt;=80%)</span>
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
                                {predictedTarget.confidence !== null ? (
                                    <>
                                        <div className="conf-bar-bg">
                                            <div className="conf-bar-fill" style={{ width: `${predictedTarget.confidence}%` }}></div>
                                        </div>
                                        <span className="conf-value">{predictedTarget.confidence}%</span>
                                    </>
                                ) : (
                                    <span className="conf-value text-dim">N/A</span>
                                )}
                            </div>
                        </div>
                        <div className="pred-item">
                            <label>EST. TIME:</label>
                            <span className="countdown-value">
                                {countdown !== null && countdown > 0
                                    ? formatCountdown(countdown)
                                    : 'N/A (Awaiting pattern)'
                                }
                            </span>
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
                    {forecastData.length > 0 ? (
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
                    ) : (
                        <div className="empty-forecast">
                            <span>No historical traffic recorded for projection</span>
                        </div>
                    )}
                </div>
                <div className="forecast-legend">
                    <span className="fl-item"><span className="fl-dot current"></span> Historical</span>
                    <span className="fl-item"><span className="fl-dot forecast"></span> Statistical Projection (α=0.4)</span>
                </div>
            </div>

            <div className="predictive-footer">
                <TriangleAlert size={12} />
                {trendDirection === 'RISING'
                    ? 'Surge detected in recent traffic window. Elevated vigilance advised.'
                    : trendDirection === 'FALLING'
                        ? 'Traffic volume trending downward across recent periods.'
                        : 'Traffic volume stable across baseline window.'
                }
            </div>
        </div>
    );
};

export default PredictiveAnalytics;

import React from 'react';
import { useRealTime } from '../context/RealTimeContext';
import { BrainCircuit, TrendingUp, AlertTriangle, Radio } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import './PredictiveAnalytics.css';

const PredictiveAnalytics = () => {
    const { metrics } = useRealTime();

    if (!metrics) return <div className="predictive-loading">Synchronizing Predictive Engine...</div>;

    // Simulated data for trend forecast
    const forecastData = [
        { time: '14:00', current: 45, forecast: 45 },
        { time: '15:00', current: 52, forecast: 52 },
        { time: '16:00', current: 48, forecast: 48 },
        { time: '17:00', current: 61, forecast: 65 },
        { time: '18:00', forecast: 72 },
        { time: '19:00', forecast: 85 },
        { time: '20:00', forecast: 78 },
    ];

    const getRiskLevel = (score) => {
        if (score > 80) return { label: 'CRITICAL', class: 'risk-critical' };
        if (score > 60) return { label: 'HIGH', class: 'risk-high' };
        if (score > 30) return { label: 'MEDIUM', class: 'risk-medium' };
        return { label: 'LOW', class: 'risk-low' };
    };

    const risk = getRiskLevel(metrics.avgThreatScore);

    return (
        <div className="predictive-container">
            <div className="predictive-header">
                <h3>PREDICTIVE ANALYTICS</h3>
                <div className="engine-status">
                    <BrainCircuit size={14} /> LSTM-V3 ACTIVE
                </div>
            </div>

            <div className="predictive-grid">
                {/* Risk Score Widget */}
                <div className="risk-widget">
                    <label>AGGREGATE RISK SCORE</label>
                    <div className={`risk-value ${risk.class}`}>
                        {metrics.avgThreatScore}%
                        <span>{risk.label}</span>
                    </div>
                    <div className="risk-meter">
                        <div className="meter-fill" style={{ width: `${metrics.avgThreatScore}%`, background: `linear-gradient(90deg, #00ff41, ${risk.class === 'risk-critical' ? '#ff0055' : '#f77f00'})` }}></div>
                    </div>
                </div>

                {/* Prediction Box */}
                <div className="prediction-box">
                    <div className="prediction-header">
                        <Radio size={14} className="pulse-icon" /> NEXT ATTACK PREDICTION
                    </div>
                    <div className="prediction-content">
                        <div className="pred-item">
                            <label>LIKELY TARGET:</label>
                            <span>SSH HONEYPOT (PORT 2222)</span>
                        </div>
                        <div className="pred-item">
                            <label>CONFIDENCE:</label>
                            <span className="conf-bar">87.4%</span>
                        </div>
                        <div className="pred-item">
                            <label>EST. TIME:</label>
                            <span>T-MINUS 14m 22s</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Trend Forecast */}
            <div className="trend-forecast">
                <div className="trend-header">
                    <TrendingUp size={14} /> ATTACK VOLUME FORECAST
                </div>
                <div className="forecast-chart">
                    <ResponsiveContainer width="100%" height={120}>
                        <AreaChart data={forecastData}>
                            <defs>
                                <linearGradient id="colorForecast" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#4cc9f0" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#4cc9f0" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <Area type="monotone" dataKey="forecast" stroke="#4cc9f0" fillOpacity={1} fill="url(#colorForecast)" strokeDasharray="5 5" />
                            <Area type="monotone" dataKey="current" stroke="#4cc9f0" fillOpacity={0} strokeWidth={3} />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>
            </div>

            <div className="predictive-footer">
                <AlertTriangle size={12} /> Expected 20% surge in traffic within next 2 hours.
            </div>
        </div>
    );
};

export default PredictiveAnalytics;

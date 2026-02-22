import React, { useState, useEffect, useMemo } from 'react';
import { FaShieldAlt, FaExclamationTriangle, FaInfoCircle, FaGlobe, FaSearch, FaHistory } from 'react-icons/fa';

/**
 * ThreatIntelWidget - A professional-grade UI component for IP security enrichment.
 * Features glassy aesthetics, micro-animations, and concise data delivery.
 */
const ThreatIntelWidget = ({ ip }) => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    useEffect(() => {
        if (ip) {
            fetchEnrichment(ip);
        }
    }, [ip]);

    const fetchEnrichment = async (targetIp) => {
        setLoading(true);
        setError(null);
        try {
            const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
            const response = await fetch(`${apiUrl}/api/v1/enrich/ip/${targetIp}`);

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || 'Failed to sync with global intel');
            }

            const result = await response.json();
            setData(result);
        } catch (err) {
            console.error('[IntelWidget Error]', err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const status = useMemo(() => {
        if (!data) return 'UNKNOWN';
        const score = data.abuse_ipdb?.abuse_confidence_score || 0;
        if (score > 80) return 'CRITICAL';
        if (score > 40) return 'SUSPICIOUS';
        return 'CLEAN';
    }, [data]);

    const getStatusColor = (lvl) => {
        switch (lvl) {
            case 'CRITICAL': return '#ef4444';
            case 'SUSPICIOUS': return '#f59e0b';
            case 'CLEAN': return '#10b981';
            default: return '#94a3b8';
        }
    };

    if (!ip) return null;

    return (
        <div className="threat-intel-pro">
            <div className="pro-header">
                <div className="header-main">
                    <FaShieldAlt className="header-icon" />
                    <span className="ip-title">{ip}</span>
                </div>
                <div className={`status-badge status-${status.toLowerCase()}`}>
                    {status}
                </div>
            </div>

            {loading ? (
                <div className="pro-loading">
                    <div className="skeleton-line" />
                    <div className="skeleton-grid">
                        <div className="skeleton-box" />
                        <div className="skeleton-box" />
                    </div>
                </div>
            ) : error ? (
                <div className="pro-error">
                    <FaExclamationTriangle />
                    <span>{error}</span>
                </div>
            ) : data ? (
                <div className="pro-body">
                    <div className="metrics-row">
                        <div className="metric-item">
                            <label>Confidence</label>
                            <span className="value" style={{ color: getStatusColor(status) }}>
                                {data.abuse_ipdb?.abuse_confidence_score || 0}%
                            </span>
                        </div>
                        <div className="metric-item">
                            <label>Pulses</label>
                            <span className="value">
                                {data.alienvault_otx?.pulse_count || 0}
                            </span>
                        </div>
                    </div>

                    <div className="details-list">
                        <div className="detail-row">
                            <FaGlobe />
                            <span className="label">Domain:</span>
                            <span className="text">{data.abuse_ipdb?.domain || 'Unknown'}</span>
                        </div>
                        <div className="detail-row">
                            <FaSearch />
                            <span className="label">Usage:</span>
                            <span className="text">{data.abuse_ipdb?.usage_type || 'Generic'}</span>
                        </div>
                        <div className="detail-row">
                            <FaHistory />
                            <span className="label">Reports:</span>
                            <span className="text">{data.abuse_ipdb?.total_reports || 0} Total</span>
                        </div>
                    </div>

                    {data.abuse_ipdb?.last_reported_at && (
                        <div className="footer-timestamp">
                            Last Reported: {new Date(data.abuse_ipdb.last_reported_at).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}
                        </div>
                    )}
                </div>
            ) : null}

            <style jsx>{`
                .threat-intel-pro {
                    background: rgba(17, 24, 39, 0.7);
                    backdrop-filter: blur(20px);
                    border: 1px solid rgba(255, 255, 255, 0.08);
                    border-radius: 16px;
                    padding: 20px;
                    width: 340px;
                    font-family: 'Outfit', 'Inter', sans-serif;
                    color: #f1f5f9;
                    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
                    transition: transform 0.2s ease;
                }
                .pro-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 20px;
                }
                .header-main { display: flex; align-items: center; gap: 10px; }
                .header-icon { color: #3b82f6; font-size: 1.2rem; }
                .ip-title { font-weight: 600; font-size: 1rem; color: #f8fafc; }
                .status-badge {
                    padding: 4px 10px;
                    border-radius: 6px;
                    font-size: 0.7rem;
                    font-weight: 700;
                    letter-spacing: 0.05em;
                }
                .status-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
                .status-suspicious { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
                .status-clean { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
                
                .metrics-row {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 12px;
                    margin-bottom: 20px;
                }
                .metric-item {
                    background: rgba(31, 41, 55, 0.5);
                    padding: 12px;
                    border-radius: 12px;
                    text-align: center;
                    border: 1px solid rgba(255, 255, 255, 0.05);
                }
                .metric-item label { display: block; font-size: 0.7rem; color: #94a3b8; margin-bottom: 4px; }
                .metric-item .value { font-size: 1.4rem; font-weight: 700; }

                .details-list { display: flex; flex-direction: column; gap: 10px; }
                .detail-row { display: flex; align-items: center; gap: 8px; font-size: 0.85rem; }
                .detail-row svg { color: #64748b; font-size: 0.9rem; }
                .detail-row .label { color: #64748b; margin-right: 4px; }
                .detail-row .text { color: #cbd5e1; font-weight: 500; }

                .footer-timestamp {
                    margin-top: 20px;
                    padding-top: 12px;
                    border-top: 1px solid rgba(255, 255, 255, 0.05);
                    font-size: 0.7rem;
                    color: #64748b;
                    text-align: right;
                }

                .pro-loading .skeleton-line { height: 12px; background: rgba(255,255,255,0.05); border-radius: 6px; margin-bottom: 12px; width: 60%; }
                .pro-loading .skeleton-box { height: 60px; background: rgba(255,255,255,0.05); border-radius: 12px; }

                .pro-error { color: #f87171; display: flex; align-items: center; gap: 10px; font-size: 0.9rem; }
            `}</style>
        </div>
    );
};

export default ThreatIntelWidget;

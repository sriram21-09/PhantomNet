import React, { useState, useEffect, useMemo } from 'react';
import { FaShieldAlt, FaExclamationTriangle, FaInfoCircle, FaGlobe, FaSearch, FaHistory } from 'react-icons/fa';
import './ThreatIntelWidget.css';

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
            // Vite replacement for process.env
            const apiUrl = import.meta.env.VITE_API_URL || '';
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
        </div>
    );
};

export default ThreatIntelWidget;

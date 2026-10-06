import React, { useState, useEffect, useCallback } from 'react';
import { Target, Zap, ShieldAlert, Clock, Info, Crosshair, Fingerprint, TriangleAlert, RotateCcw } from 'lucide-react';
import { normalizeThreatScore } from '../utils/threatScore';
import './AttackAttribution.css';

const TOOL_ICONS = {
    'Port Scanner Pattern': '🔍',
    'SSH Auth Scanner': '🔑',
    'Exploitation Suite Pattern': '💀',
    'Web Vulnerability Scanner': '🕷️',
    'Automated Script Pattern': '⚙️',
    'Unclassified Traffic': '📊',
};

const AttackAttribution = () => {
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [errorCode, setErrorCode] = useState(null);
    const [topAttackers, setTopAttackers] = useState([]);
    const [selectedIP, setSelectedIP] = useState(null);
    const [profile, setProfile] = useState(null);
    const [profileLoading, setProfileLoading] = useState(false);

    // Fetch top attackers list from backend
    const fetchTopAttackers = useCallback(async () => {
        try {
            const res = await fetch('/api/v1/attribution/top-attackers?limit=10&hours=72', {
                credentials: 'include',
            });

            if (res.status === 401) {
                setErrorCode(401);
                throw new Error('Authentication required for attribution telemetry');
            }
            if (res.status === 403) {
                setErrorCode(403);
                throw new Error('Access forbidden to attribution telemetry');
            }
            if (!res.ok) {
                setErrorCode(res.status);
                throw new Error(`Unable to fetch attacker attribution (status: ${res.status})`);
            }

            const data = await res.json();
            const attackers = data.attackers || [];
            setTopAttackers(attackers);

            // Automatically select first attacker if none selected
            setSelectedIP(prev => {
                if (prev && attackers.some(a => a.ip === prev)) {
                    return prev;
                }
                return attackers.length > 0 ? attackers[0].ip : null;
            });

            setError(null);
            setErrorCode(null);
            setLoading(false);
        } catch (err) {
            setError(err.message || 'Failed to load attribution data');
            setLoading(false);
        }
    }, []);

    // Fetch profile for the currently selected IP
    const fetchProfile = useCallback(async (ip) => {
        if (!ip) {
            setProfile(null);
            return;
        }
        setProfileLoading(true);
        try {
            const res = await fetch(`/api/v1/attribution/profile/${encodeURIComponent(ip)}`, {
                credentials: 'include',
            });

            if (res.status === 401) {
                setErrorCode(401);
                throw new Error('Authentication required for attacker profile');
            }
            if (!res.ok) {
                throw new Error(`Failed to load profile for ${ip}`);
            }

            const data = await res.json();
            setProfile(data);
        } catch (err) {
            console.error('Error fetching attacker profile:', err);
            setProfile(null);
        } finally {
            setProfileLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchTopAttackers();
        const interval = setInterval(fetchTopAttackers, 30000);
        return () => clearInterval(interval);
    }, [fetchTopAttackers]);

    useEffect(() => {
        if (selectedIP) {
            fetchProfile(selectedIP);
        }
    }, [selectedIP, fetchProfile]);

    if (loading && topAttackers.length === 0 && !error) {
        return (
            <div className="attribution-container">
                <div className="attribution-loading">
                    <Crosshair size={24} className="spin" />
                    <span>Analyzing Attacker Signatures...</span>
                </div>
            </div>
        );
    }

    if (error && topAttackers.length === 0) {
        return (
            <div className="attribution-container">
                <div className="attribution-header">
                    <h3><Fingerprint size={16} /> ATTACK ATTRIBUTION</h3>
                </div>
                <div className="attribution-error-state">
                    <ShieldAlert size={28} className="error-icon" />
                    <div className="error-title">
                        {errorCode === 401 ? 'Authentication Required' : 'Attribution Unavailable'}
                    </div>
                    <div className="error-detail">{error}</div>
                    <button className="retry-btn" onClick={fetchTopAttackers}>
                        <RotateCcw size={14} /> Retry Telemetry
                    </button>
                </div>
            </div>
        );
    }

    if (!topAttackers.length) {
        return (
            <div className="attribution-container">
                <div className="attribution-header">
                    <h3><Fingerprint size={16} /> ATTACK ATTRIBUTION</h3>
                </div>
                <div className="attribution-empty-state">
                    <p>No active attacker signatures identified in recent window.</p>
                </div>
            </div>
        );
    }

    const currentProfile = profile?.profile || {};
    const timeline = profile?.timeline || {};
    const progression = profile?.progression || [
        { name: 'RECON', active: false },
        { name: 'EXPLOIT', active: false },
        { name: 'LATERAL', active: false },
        { name: 'EXFIL', active: false },
    ];
    const confidence = profile?.confidence ?? 0;
    const soph = currentProfile.sophistication || { level: 'Analyzing...', class: 'level-low' };
    const tools = currentProfile.tools_detected || ['Unclassified Traffic'];
    const intent = currentProfile.intent || 'Unknown / insufficient evidence';
    const protocols = currentProfile.protocols || [];

    const firstSeen = timeline.first_seen ? new Date(timeline.first_seen).toLocaleTimeString() : 'N/A';
    const lastSeen = timeline.last_seen ? new Date(timeline.last_seen).toLocaleTimeString() : 'N/A';
    const totalEvents = timeline.total_events ?? 0;

    return (
        <div className="attribution-container">
            <div className="attribution-header">
                <h3><Fingerprint size={16} /> ATTACK ATTRIBUTION</h3>
                <div className="confidence-badge">
                    <div className="confidence-ring" style={{ '--conf': `${confidence * 3.6}deg` }}>
                        <span>{confidence}%</span>
                    </div>
                    <label>CONFIDENCE</label>
                </div>
            </div>

            {/* Attacker Selector */}
            <div className="attacker-selector">
                <label>IDENTIFIED ATTACKERS ({topAttackers.length})</label>
                <div className="attacker-chips">
                    {topAttackers.slice(0, 5).map(a => {
                        const scoreInfo = normalizeThreatScore(a.max_threat_score);
                        return (
                            <button
                                key={a.ip}
                                className={`attacker-chip ${a.ip === selectedIP ? 'selected' : ''}`}
                                onClick={() => setSelectedIP(a.ip)}
                            >
                                <span className={`chip-dot ${
                                    scoreInfo.severity === 'CRITICAL' ? 'critical' :
                                    scoreInfo.severity === 'HIGH' ? 'high' : 'low'
                                }`}></span>
                                {a.ip}
                            </button>
                        );
                    })}
                </div>
            </div>

            <div className="profiler-grid">
                {/* Attacker Profile */}
                <div className="profile-section">
                    <div className="profile-item">
                        <label><Target size={14} /> ATTACKER IP</label>
                        <div className="value mono-text">
                            {profileLoading ? 'Loading profile...' : (selectedIP || 'N/A')}
                        </div>
                    </div>
                    <div className="profile-item">
                        <label><Zap size={14} /> THREAT TIER</label>
                        <div className={`value ${soph.class || 'level-low'}`}>
                            {soph.level || 'Unknown / insufficient evidence'}
                        </div>
                    </div>
                </div>

                {/* Intent & Tools */}
                <div className="toolset-section">
                    <div className="tool-intent-row">
                        <div className="intent-box">
                            <label><TriangleAlert size={12} /> INFERRED INTENT</label>
                            <div className="intent-value">{intent}</div>
                        </div>
                        <div className="protocols-box">
                            <label>PROTOCOLS OBSERVED</label>
                            <div className="proto-tags">
                                {protocols.length > 0 ? (
                                    protocols.map(p => (
                                        <span key={p} className="proto-tag">{p}</span>
                                    ))
                                ) : (
                                    <span className="proto-tag">None recorded</span>
                                )}
                            </div>
                        </div>
                    </div>
                    <div className="tool-list">
                        <label>OBSERVED SIGNATURES / PATTERNS:</label>
                        <div className="tags">
                            {tools.map(tool => (
                                <span key={tool} className="tag">
                                    {TOOL_ICONS[tool] || '📊'} {tool}
                                </span>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            {/* Attack Timeline */}
            <div className="attack-timeline">
                <h4>ATTACK PROGRESSION</h4>
                <div className="timeline-stats">
                    <div className="t-stat">
                        <label><Clock size={12} /> FIRST SEEN:</label>
                        <span>{firstSeen}</span>
                    </div>
                    <div className="t-stat">
                        <label><Clock size={12} /> LAST SEEN:</label>
                        <span>{lastSeen}</span>
                    </div>
                    <div className="t-stat">
                        <label>TOTAL EVENTS:</label>
                        <span className="event-count-value">{totalEvents}</span>
                    </div>
                </div>
                <div className="timeline-steps">
                    {progression.map((step, i) => (
                        <React.Fragment key={step.name}>
                            <div className={`step ${step.active ? 'active' : ''}`}>
                                <div className="step-marker">
                                    {step.active && <div className="step-pulse"></div>}
                                </div>
                                <div className="step-label">{step.name}</div>
                            </div>
                            {i < progression.length - 1 && (
                                <div className={`step-connector ${step.active && progression[i + 1]?.active ? 'active' : ''}`}></div>
                            )}
                        </React.Fragment>
                    ))}
                </div>
            </div>

            <div className="attribution-footer">
                <Info size={12} />
                {profile?.evidence_source ? (
                    <span>Source: {profile.evidence_source}</span>
                ) : (
                    <span>Source: Database (packet_logs telemetry aggregation)</span>
                )}
            </div>
        </div>
    );
};

export default AttackAttribution;

import React, { useState } from 'react';
import {
    Clock, Shield, Globe, Zap, ChevronDown, ChevronUp,
    AlertTriangle, Terminal, Activity, Target
} from 'lucide-react';
import './EventTimeline.css';

const THREAT_COLORS = {
    CRITICAL: { color: '#ef4444', bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.2)' },
    HIGH: { color: '#f97316', bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.2)' },
    MEDIUM: { color: '#eab308', bg: 'rgba(234,179,8,0.08)', border: 'rgba(234,179,8,0.2)' },
    LOW: { color: '#22c55e', bg: 'rgba(34,197,94,0.05)', border: 'rgba(34,197,94,0.1)' },
};

const getLevelStyle = (level) => THREAT_COLORS[level] || { color: '#64748b', bg: 'rgba(100,116,139,0.05)', border: 'rgba(100,116,139,0.1)' };

const getScoreWidth = (score) => `${Math.min(Math.max(score || 0, 0), 100)}%`;

const detectPatterns = (text) => {
    if (!text) return [];
    const patterns = [];
    if (/union\s+select|select.*from|insert\s+into|drop\s+table/i.test(text)) patterns.push({ label: 'SQLi', color: '#ef4444' });
    if (/<script>|javascript:|onerror=|onload=/i.test(text)) patterns.push({ label: 'XSS', color: '#f97316' });
    if (/\.\.[\/\\]|etc\/passwd|cmd\.exe/i.test(text)) patterns.push({ label: 'Path Traversal', color: '#eab308' });
    if (/nmap|masscan|sqlmap|nikto/i.test(text)) patterns.push({ label: 'Scanner', color: '#a855f7' });
    if (/base64_decode|eval\(|exec\(|system\(/i.test(text)) patterns.push({ label: 'Code Exec', color: '#06b6d4' });
    return patterns;
};

const EventTimeline = ({ events, onSelectEvent, selectedEventId }) => {
    // Added index for event numbering
    const [expandedId, setExpandedId] = useState(null);

    if (!events || events.length === 0) {
        return (
            <div className="timeline-empty">
                <Shield className="tl-empty-icon" />
                <p>No events match your current query.</p>
                <span>Try adjusting filters or using a Quick Template from the left panel.</span>
            </div>
        );
    }

    const handleClick = (event) => {
        const newExpanded = expandedId === event.id ? null : event.id;
        setExpandedId(newExpanded);
        onSelectEvent(event);
    };

    return (
        <div className="event-timeline">
            {events.map((event, idx) => {
                const style = getLevelStyle(event.threat_level);
                const isSelected = selectedEventId === event.id;
                const isExpanded = expandedId === event.id;
                const patterns = detectPatterns(event.raw_data || event.payload_content || event.attack_type || '');
                const payload = event.raw_data ||
                    `${event.attack_type || 'UNKNOWN_ATTACK'} — src=${event.src_ip}:${event.src_port || '?'} dst=${event.dst_ip}:${event.dst_port} proto=${event.protocol}`;

                return (
                    <div
                        key={event.id}
                        className={`timeline-item ${isSelected ? 'selected' : ''} ${isExpanded ? 'expanded' : ''}`}
                        onClick={() => handleClick(event)}
                        style={isSelected ? { borderLeftColor: style.color } : {}}
                    >
                        <span className="event-number" style={{ color: style.color, marginRight: '0.5rem' }}>{idx + 1}.</span>
                        {/* ── Top Row ── */}
                        <div className="tl-top">
                            <div
                                className="tl-level-dot"
                                style={{ background: style.color, boxShadow: `0 0 6px ${style.color}` }}
                            />

                            <div className="tl-meta">
                                <span className="tl-time">
                                    <Clock className="w-2.5 h-2.5" />
                                    {new Date(event.timestamp).toLocaleString()}
                                </span>
                                <span
                                    className="tl-level-badge"
                                    style={{ color: style.color, background: style.bg, borderColor: style.border }}
                                >
                                    {event.threat_level || 'UNK'}
                                </span>
                                <span className="tl-proto">{event.protocol}</span>
                            </div>

                            <div className="tl-score-ring" style={{ '--score-color': style.color }}>
                                <span style={{ color: style.color }}>{Math.round(event.threat_score)}</span>
                            </div>

                            <div className="tl-expand-btn">
                                {isExpanded
                                    ? <ChevronUp className="w-3.5 h-3.5" />
                                    : <ChevronDown className="w-3.5 h-3.5" />
                                }
                            </div>
                        </div>

                        {/* ── IPs Row ── */}
                        <div className="tl-ips">
                            <span className="tl-ip src">{event.src_ip}
                                {event.src_port ? <span className="tl-port">:{event.src_port}</span> : null}
                            </span>
                            <Globe className="tl-arrow" />
                            <span className="tl-ip dst">{event.dst_ip}
                                {event.dst_port ? <span className="tl-port">:{event.dst_port}</span> : null}
                            </span>
                        </div>

                        {/* ── Attack type + patterns ── */}
                        <div className="tl-attack">
                            <Zap className="w-3 h-3" style={{ color: style.color }} />
                            <span className="tl-attack-text">{event.attack_type || 'Observed Activity'}</span>
                            {patterns.map(p => (
                                <span
                                    key={p.label}
                                    className="tl-pattern-tag"
                                    style={{ color: p.color, borderColor: `${p.color}40`, background: `${p.color}10` }}
                                >
                                    {p.label}
                                </span>
                            ))}
                        </div>

                        {/* ── Score Bar ── */}
                        <div className="tl-score-bar-wrap">
                            <div
                                className="tl-score-bar"
                                style={{
                                    width: getScoreWidth(event.threat_score),
                                    background: `linear-gradient(90deg, ${style.color}80, ${style.color}20)`
                                }}
                            />
                        </div>

                        {/* ── Expanded Details ── */}
                        {isExpanded && (
                            <div className="tl-expanded animate-expand">
                                <div className="tl-exp-grid">
                                    <div className="tl-exp-item">
                                        <span className="tl-exp-label">Event ID</span>
                                        <span className="tl-exp-val mono">#{event.id}</span>
                                    </div>
                                    <div className="tl-exp-item">
                                        <span className="tl-exp-label">Confidence</span>
                                        <span className="tl-exp-val">{((event.confidence || 0) * 100).toFixed(1)}%</span>
                                    </div>
                                    <div className="tl-exp-item">
                                        <span className="tl-exp-label">Packet Size</span>
                                        <span className="tl-exp-val">{event.length || 'N/A'} bytes</span>
                                    </div>
                                    <div className="tl-exp-item">
                                        <span className="tl-exp-label">Is Malicious</span>
                                        <span className={`tl-exp-val ${event.is_malicious ? 'danger' : 'safe'}`}>
                                            {event.is_malicious ? '⚠ Confirmed' : '✓ No'}
                                        </span>
                                    </div>
                                </div>

                                <div className="tl-payload">
                                    <div className="tl-payload-header">
                                        <Terminal className="w-3 h-3" />
                                        <span>Payload Analysis</span>
                                        {patterns.map(p => (
                                            <span
                                                key={p.label}
                                                className="tl-pattern-tag"
                                                style={{ color: p.color, borderColor: `${p.color}40`, background: `${p.color}10` }}
                                            >
                                                {p.label} detected
                                            </span>
                                        ))}
                                    </div>
                                    <pre className="tl-payload-pre">{payload}</pre>
                                </div>

                                <div className="tl-exp-actions">
                                    <span className="tl-exp-hint">
                                        <Activity className="w-3 h-3 text-cyan-400" />
                                        Click "IP Correlation" tab for related events
                                    </span>
                                    <span className="tl-exp-hint">
                                        <Target className="w-3 h-3 text-purple-400" />
                                        Investigation panel → right sidebar
                                    </span>
                                </div>
                            </div>
                        )}
                    </div>
                );
            })}
        </div>
    );
};

export default EventTimeline;

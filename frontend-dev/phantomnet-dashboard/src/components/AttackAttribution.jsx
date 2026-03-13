import React, { useState, useMemo, useEffect } from 'react';
import { useRealTime } from '../context/RealTimeContext';
import { Target, Zap, ShieldAlert, Clock, Info, ChevronDown, Crosshair, Fingerprint, TriangleAlert } from 'lucide-react';
import './AttackAttribution.css';

const TOOL_ICONS = {
    'Nmap': '🔍',
    'Metasploit': '💀',
    'Hydra': '🔑',
    'Nikto': '🕷️',
    'Custom Script': '⚙️',
    'Unknown Scanner': '❓',
};

const AttackAttribution = () => {
    const { events } = useRealTime();
    const [selectedIP, setSelectedIP] = useState(null);

    // Get unique attacker IPs (sorted by threat)
    const attackerIPs = useMemo(() => {
        const ipMap = {};
        events.forEach(e => {
            if (!e.src_ip) return;
            if (!ipMap[e.src_ip]) {
                ipMap[e.src_ip] = { ip: e.src_ip, events: [], maxScore: 0 };
            }
            ipMap[e.src_ip].events.push(e);
            ipMap[e.src_ip].maxScore = Math.max(ipMap[e.src_ip].maxScore, e.threat_score || 0);
        });
        return Object.values(ipMap).sort((a, b) => b.maxScore - a.maxScore).slice(0, 10);
    }, [events]);

    // Auto-select most threatening IP
    useEffect(() => {
        if (!selectedIP && attackerIPs.length > 0) {
            setSelectedIP(attackerIPs[0].ip);
        }
    }, [attackerIPs, selectedIP]);

    const currentAttacker = useMemo(() => {
        return attackerIPs.find(a => a.ip === selectedIP) || attackerIPs[0] || null;
    }, [attackerIPs, selectedIP]);

    if (!currentAttacker || events.length === 0) {
        return (
            <div className="attribution-container">
                <div className="attribution-loading">
                    <Crosshair size={24} className="spin" />
                    <span>Analyzing Attacker Signatures...</span>
                </div>
            </div>
        );
    }

    const attackerEvents = currentAttacker.events;
    const latestAttack = attackerEvents[0];
    const maxScore = currentAttacker.maxScore;
    const avgScore = attackerEvents.length > 0 ? attackerEvents.reduce((sum, e) => sum + (e.threat_score || 0), 0) / attackerEvents.length : 0;

    const getSophistication = (score, count) => {
        if (score > 90 && count > 10) return { level: 'Advanced (State-Actor)', class: 'level-vhigh', icon: '🔴' };
        if (score > 70) return { level: 'Intermediate (Organized)', class: 'level-high', icon: '🟠' };
        return { level: 'Amateur (Script Kiddie)', class: 'level-low', icon: '🟢' };
    };

    const detectTools = (proto, attackType, score) => {
        const tools = [];
        if ((proto === 'TCP' || proto === 'SSH') && score > 60) tools.push('Nmap');
        if (proto === 'SSH' && (attackType === 'MALICIOUS' || score > 70)) tools.push('Hydra');
        if (score > 80) tools.push('Metasploit');
        if (proto === 'HTTP' && score > 50) tools.push('Nikto');
        if (proto === 'FTP' && score > 40) tools.push('Custom Script');
        if (tools.length === 0) tools.push('Unknown Scanner');
        return tools;
    };

    const inferIntent = (attackType, count, score) => {
        if (score > 85 || attackType === 'MALICIOUS') {
            return count > 15 ? 'Exfiltration' : 'Exploitation';
        }
        if (count > 8) return 'Lateral Movement';
        return 'Reconnaissance';
    };

    const getProgression = (evts) => {
        const stages = [
            { name: 'RECON', active: evts.length > 0 },
            { name: 'EXPLOIT', active: evts.some(e => (e.threat_score || 0) > 60) },
            { name: 'LATERAL', active: evts.some(e => (e.threat_score || 0) > 80) && evts.length > 10 },
            { name: 'EXFIL', active: evts.some(e => (e.threat_score || 0) > 80) && evts.length > 20 },
        ];
        return stages;
    };

    const soph = getSophistication(maxScore, attackerEvents.length);
    const tools = detectTools(latestAttack.protocol, latestAttack.attack_type, maxScore);
    const intent = inferIntent(latestAttack.attack_type, attackerEvents.length, maxScore);
    const progression = getProgression(attackerEvents);
    const confidence = Math.min(95, Math.round(avgScore * 0.7 + attackerEvents.length * 0.3 + 10));

    const firstSeen = attackerEvents.length > 0
        ? new Date(attackerEvents[attackerEvents.length - 1].timestamp).toLocaleTimeString()
        : 'N/A';
    const lastSeen = attackerEvents.length > 0
        ? new Date(attackerEvents[0].timestamp).toLocaleTimeString()
        : 'N/A';
    const protocols = [...new Set(attackerEvents.map(e => e.protocol).filter(Boolean))];

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
                <label>ACTIVE THREATS ({attackerIPs.length})</label>
                <div className="attacker-chips">
                    {attackerIPs.slice(0, 5).map(a => (
                        <button
                            key={a.ip}
                            className={`attacker-chip ${a.ip === selectedIP ? 'selected' : ''}`}
                            onClick={() => setSelectedIP(a.ip)}
                        >
                            <span className={`chip-dot ${a.maxScore > 80 ? 'critical' : a.maxScore > 40 ? 'high' : 'low'}`}></span>
                            {a.ip}
                        </button>
                    ))}
                </div>
            </div>

            <div className="profiler-grid">
                {/* Attacker Profile */}
                <div className="profile-section">
                    <div className="profile-item">
                        <label><Target size={14} /> ATTACKER IP</label>
                        <div className="value mono-text">{currentAttacker.ip}</div>
                    </div>
                    <div className="profile-item">
                        <label><Zap size={14} /> SOPHISTICATION</label>
                        <div className={`value ${soph.class}`}>{soph.icon} {soph.level}</div>
                    </div>
                </div>

                {/* Intent & Tools */}
                <div className="toolset-section">
                    <div className="tool-intent-row">
                        <div className="intent-box">
                            <label><TriangleAlert size={12} /> INTENT</label>
                            <div className="intent-value">{intent}</div>
                        </div>
                        <div className="protocols-box">
                            <label>PROTOCOLS</label>
                            <div className="proto-tags">
                                {protocols.map(p => (
                                    <span key={p} className="proto-tag">{p}</span>
                                ))}
                            </div>
                        </div>
                    </div>
                    <div className="tool-list">
                        <label>DETECTED TOOLS:</label>
                        <div className="tags">
                            {tools.map(tool => (
                                <span key={tool} className="tag">
                                    {TOOL_ICONS[tool] || '🔧'} {tool}
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
                        <span className="event-count-value">{attackerEvents.length}</span>
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
                                <div className={`step-connector ${step.active && progression[i + 1].active ? 'active' : ''}`}></div>
                            )}
                        </React.Fragment>
                    ))}
                </div>
            </div>

            <div className="attribution-footer">
                <Info size={12} />
                {attackerEvents.length > 15
                    ? `⚠ Persistent threat detected — ${attackerEvents.length} events from ${currentAttacker.ip} via ${latestAttack.protocol}`
                    : `Monitoring ${currentAttacker.ip} — ${attackerEvents.length} events recorded`
                }
            </div>
        </div>
    );
};

export default AttackAttribution;

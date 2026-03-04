import React from 'react';
import { useRealTime } from '../context/RealTimeContext';
import { Target, Zap, ShieldAlert, Clock, Info } from 'lucide-react';
import './AttackAttribution.css';

const AttackAttribution = () => {
    const { events } = useRealTime();

    // Derive attribution from the latest malicious event
    const latestAttack = events.find(e => e.attack_type === 'MALICIOUS' || e.threat_score > 70) || events[0];

    if (!latestAttack) return <div className="attribution-loading">Analyzing Attacker Signatures...</div>;

    const getSophistication = (score) => {
        if (score > 90) return { level: 'Advanced (State-Actor)', class: 'level-vhigh' };
        if (score > 70) return { level: 'Intermediate (Organized)', class: 'level-high' };
        return { level: 'Amateur (Script Kiddie)', class: 'level-low' };
    };

    const soph = getSophistication(latestAttack.threat_score);

    // Calculate timeline stats for this IP
    const attackerEvents = events.filter(e => e.src_ip === latestAttack.src_ip);
    const totalEvents = attackerEvents.length;
    const lastSeen = attackerEvents.length > 0 ? new Date(attackerEvents[0].timestamp).toLocaleTimeString() : 'N/A';
    const firstSeen = attackerEvents.length > 0 ? new Date(attackerEvents[attackerEvents.length - 1].timestamp).toLocaleTimeString() : 'N/A';

    return (
        <div className="attribution-container">
            <div className="attribution-header">
                <h3>ATTACK ATTRIBUTION</h3>
                <span className="confidence">CONFIDENCE: {Math.round(latestAttack.threat_score * 0.9 + 5)}%</span>
            </div>

            <div className="profiler-grid">
                {/* Attacker Profile */}
                <div className="profile-section">
                    <div className="profile-item">
                        <label><Target size={14} /> ATTACKER IP</label>
                        <div className="value">{latestAttack.src_ip}</div>
                    </div>
                    <div className="profile-item">
                        <label><Zap size={14} /> SOPHISTICATION</label>
                        <div className={`value ${soph.class}`}>{soph.level}</div>
                    </div>
                </div>

                {/* Intent & Tools */}
                <div className="toolset-section">
                    <div className="tool-tag">INTENT: {latestAttack.attack_type || 'RECONNAISSANCE'}</div>
                    <div className="tool-list">
                        <label>DETECTED TOOLS:</label>
                        <div className="tags">
                            <span className="tag">Nmap</span>
                            <span className="tag">Metasploit</span>
                            <span className="tag">Hydra</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Attack Timeline Simulation */}
            <div className="attack-timeline">
                <h4>ATTACK PROGRESSION</h4>
                <div className="timeline-stats">
                    <div className="t-stat"><label>FIRST SEEN:</label> <span>{firstSeen}</span></div>
                    <div className="t-stat"><label>LAST SEEN:</label> <span>{lastSeen}</span></div>
                    <div className="t-stat"><label>TOTAL EVENTS:</label> <span>{totalEvents}</span></div>
                </div>
                <div className="timeline-steps">
                    <div className="step active">
                        <div className="step-marker"></div>
                        <div className="step-label">RECON</div>
                    </div>
                    <div className="step active">
                        <div className="step-marker"></div>
                        <div className="step-label">EXPLOIT</div>
                    </div>
                    <div className="step">
                        <div className="step-marker"></div>
                        <div className="step-label">LATERAL</div>
                    </div>
                    <div className="step">
                        <div className="step-marker"></div>
                        <div className="step-label">EXFIL</div>
                    </div>
                </div>
            </div>

            <div className="attribution-footer">
                <Info size={12} /> Persistence indicators detected in protocol {latestAttack.protocol}
            </div>
        </div>
    );
};

export default AttackAttribution;

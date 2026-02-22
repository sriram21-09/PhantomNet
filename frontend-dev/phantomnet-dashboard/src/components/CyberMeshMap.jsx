import React, { useEffect, useState, useMemo } from 'react';
import './CyberMeshMap.css';

const CyberMeshMap = () => {
    const [attacks, setAttacks] = useState([]);
    const [ghosts, setGhosts] = useState([]);
    const [latestAttack, setLatestAttack] = useState(null);
    const [terminalFeed, setTerminalFeed] = useState([]);
    const [loading, setLoading] = useState(true);

    const HUB_X = 400;
    const HUB_Y = 160;

    // Static Satellite Nodes (Global References)
    const satellites = useMemo(() => [
        { x: 140, y: 100, label: "NYC_NODE" },
        { x: 395, y: 75, label: "LDN_NODE" },
        { x: 680, y: 110, label: "TYO_NODE" },
        { x: 420, y: 90, label: "FRA_NODE" },
        { x: 700, y: 300, label: "SYD_NODE" }
    ], []);

    useEffect(() => {
        const generateGhosts = () => {
            const newGhosts = Array.from({ length: 4 }).map((_, i) => {
                const x = 50 + Math.random() * 700;
                const y = 50 + Math.random() * 300;
                const midX = (x + HUB_X) / 2;
                const midY = Math.min(y, HUB_Y) - 30;
                return {
                    id: `ghost-${i}-${Date.now()}`,
                    path: `M ${x} ${y} Q ${midX} ${midY} ${HUB_X} ${HUB_Y}`,
                    delay: Math.random() * 5
                };
            });
            setGhosts(newGhosts);
        };

        const fetchData = async () => {
            try {
                const eventsRes = await fetch('/analyze-traffic');
                const eventsData = await eventsRes.json();

                if (eventsData.status === "success") {
                    const validPoints = eventsData.data
                        .filter(e => e.packet_info.lat && e.packet_info.lon)
                        .map((e, idx) => {
                            const x = ((e.packet_info.lon + 180) * (800 / 360));
                            const y = ((90 - e.packet_info.lat) * (400 / 180));
                            const midX = (x + HUB_X) / 2;
                            const midY = Math.min(y, HUB_Y) - 60;
                            return {
                                id: `${e.packet_info.src}-${idx}`,
                                x, y,
                                arcPath: `M ${x} ${y} Q ${midX} ${midY} ${HUB_X} ${HUB_Y}`,
                                intensity: e.ai_analysis.threat_score,
                                ip: e.packet_info.src,
                                country: e.packet_info.location,
                                proto: e.packet_info.proto,
                                size: e.packet_info.size || Math.floor(Math.random() * 500) + 64,
                                timestamp: new Date().toLocaleTimeString()
                            };
                        });

                    setAttacks(validPoints.slice(0, 3));
                    if (validPoints.length > 0) {
                        const latest = validPoints[0];
                        setLatestAttack(latest);
                        setTerminalFeed(prev => [`> INBOUND_${latest.proto} [${latest.ip}] SIZE:${latest.size}B`, ...prev].slice(0, 4));
                    }
                }
            } catch (err) {
                console.error("Map fetch error:", err);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
        generateGhosts();
        const interval = setInterval(() => { fetchData(); generateGhosts(); }, 5000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="cyber-mesh-card pro-card ultra-v2">
            <div className="card-header hud-font small-hdr">
                <div className="header-left">
                    <div className="header-title-group">
                        <span className="glow-text mega-title">GLOBAL THREAT MESH <span className="v-tag">v2.1</span></span>
                        <div className="status-indicator">
                            <span className="pulse-dot"></span>
                            <span className="live-status">CALIBRATED // REAL-TIME_FEED</span>
                        </div>
                    </div>
                </div>
                <div className="mesh-ticker">
                    <span className="ticker-item blink">RADAR: ACTIVE</span>
                    <span className="ticker-item">SIG_STR: 98%</span>
                </div>
            </div>

            <div className="map-viewport">
                {/* Integrated Threat HUD Overlay (Chromatic Aberration Styled) */}
                {latestAttack && (
                    <div className="threat-hud-overlay condensed hud-font">
                        <div className="hud-header glass-title">SIGNAL_IDENTITY</div>
                        <div className="hud-body">
                            <div className="hud-main-info">
                                <span className="hud-val-large glowing-cyan">{latestAttack.ip}</span>
                                <span className="hud-sub">{latestAttack.country}</span>
                            </div>
                            <div className="hud-stats-grid">
                                <div className="stat-box">
                                    <span className="stat-lbl">THREAT</span>
                                    <span className={`stat-val ${latestAttack.intensity > 70 ? 'danger' : 'safe'}`}>
                                        {latestAttack.intensity.toFixed(1)}
                                    </span>
                                </div>
                                <div className="stat-box">
                                    <span className="stat-lbl">PROTO</span>
                                    <span className="stat-val">{latestAttack.proto}</span>
                                </div>
                            </div>
                            <div className="hud-terminal-feed">
                                {terminalFeed.map((line, i) => (
                                    <div key={i} className="feed-line">{line}</div>
                                ))}
                            </div>
                        </div>
                    </div>
                )}

                <svg viewBox="0 0 800 400" className="mesh-svg high-res">
                    <defs>
                        <pattern id="gridSub" width="15" height="15" patternUnits="userSpaceOnUse">
                            <path d="M 15 0 L 0 0 0 15" fill="none" stroke="rgba(59, 130, 246, 0.04)" strokeWidth="0.3" />
                        </pattern>
                        <filter id="chromatic">
                            <feOffset in="SourceGraphic" dx="-1" dy="0" result="red" />
                            <feOffset in="SourceGraphic" dx="1" dy="0" result="blue" />
                            <feBlend in="red" in2="blue" mode="screen" />
                        </filter>
                    </defs>

                    <rect width="100%" height="100%" fill="url(#gridSub)" />

                    {/* ULTRA-DETAILED LANDMASSES (Refined Coordinate Precision) */}
                    <g className="landmass-group detailed-mesh">
                        {/* North America Refined */}
                        <path className="land-path v2" d="M100,80 L120,75 L145,65 L170,70 L200,90 L225,120 L235,150 L210,185 L180,200 L140,205 L110,195 L90,170 L85,130 L95,90 Z" />
                        {/* South America Refined */}
                        <path className="land-path v2" d="M210,195 L250,210 L265,240 L260,300 L240,350 L215,360 L185,320 L180,260 L195,210 Z" />
                        {/* Eurasia / Africa Refined */}
                        <path className="land-path v2" d="M360,60 L450,55 L550,55 L650,60 L780,75 L760,150 L680,185 L580,195 L520,240 L490,320 L440,350 L380,320 L360,240 L345,160 L350,100 Z" />
                        {/* Australia Refined */}
                        <path className="land-path v2" d="M660,260 L740,270 L750,330 L670,340 L650,300 Z" />
                        {/* Additional detail segments for Greenland / Islands */}
                        <path className="island" d="M230,20 L280,30 L260,60 L220,50 Z" />
                    </g>

                    {/* Radar Sweep Animation (Dual Axis) */}
                    <line x1="0" y1="0" x2="800" y2="0" className="radar-beam-h" stroke="rgba(59, 130, 246, 0.2)" strokeWidth="1" />
                    <line x1="0" y1="0" x2="0" y2="400" className="radar-beam-v" stroke="rgba(59, 130, 246, 0.2)" strokeWidth="1" />

                    {/* Satellite Nodes */}
                    {satellites.map((s, i) => (
                        <g key={i} transform={`translate(${s.x}, ${s.y})`}>
                            <rect x="-2" y="-2" width="4" height="4" fill="var(--color-cyan)" className="sat-rect" />
                            <text y="-8" textAnchor="middle" className="sat-label hud-font">{s.label}</text>
                        </g>
                    ))}

                    {/* Ghost Arcs (Background Activity) */}
                    {ghosts.map(ghost => (
                        <path
                            key={ghost.id}
                            d={ghost.path}
                            className="ghost-arc"
                            style={{ animationDelay: `${ghost.delay}s` }}
                        />
                    ))}

                    {/* Live Attack Arcs */}
                    {attacks.map(attack => (
                        <g key={attack.id}>
                            <path
                                d={attack.arcPath}
                                className={`attack-arc-v2 ${attack.intensity > 70 ? 'danger-arc' : 'active-arc'}`}
                            />
                            <circle cx={attack.x} cy={attack.y} r="2" className="strike-origin" fill="var(--color-cyan)" />
                        </g>
                    ))}

                    {/* Central Hub (Calibrated Core) */}
                    <g transform={`translate(${HUB_X}, ${HUB_Y})`}>
                        <circle r="6" className="hub-core-v2" />
                        <circle r="15" className="hub-ring rotate" fill="none" strokeWidth="1" strokeDasharray="4 2" />
                        <circle r="25" className="hub-ring rotate-rev" fill="none" strokeWidth="0.5" strokeDasharray="2 10" />
                    </g>
                </svg>
            </div>

            <div className="map-footer v2-footer hud-font">
                <div className="meta-stream">
                    <span className="meta-tag">SYS_MODE: MONITOR</span>
                    <span className="meta-tag">OPS_LEVEL: DELTA</span>
                </div>
                <div className="timestamp-live">
                    [ CALIBRATION_FIXED_UTC: {new Date().toISOString().slice(11, 19)} ]
                </div>
            </div>
        </div>
    );
};

export default CyberMeshMap;


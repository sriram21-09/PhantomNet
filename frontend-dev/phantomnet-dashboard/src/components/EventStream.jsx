import React, { useEffect, useRef, useState, useCallback } from 'react';
import { useRealTime } from '../context/RealTimeContext';
import { Wifi, WifiOff, Volume2, VolumeX, Pause, Play } from 'lucide-react';
import { normalizeThreatScore } from '../utils/threatScore';
import './EventStream.css';

const playAlertBeep = () => {
    try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (!AudioCtx) return;
        const ctx = new AudioCtx();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(587.33, ctx.currentTime); // D5
        osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.1); // A5
        gain.gain.setValueAtTime(0.15, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.2);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start();
        osc.stop(ctx.currentTime + 0.2);
    } catch {
        // AudioContext may be restricted by autoplay policy
    }
};

const EventStream = () => {
    const { events, isConnected } = useRealTime();
    const [selectedEvent, setSelectedEvent] = useState(null);
    const [soundEnabled, setSoundEnabled] = useState(false);
    const [isPaused, setIsPaused] = useState(false);
    const [pausedEvents, setPausedEvents] = useState([]);
    const scrollRef = useRef(null);

    const displayEvents = isPaused ? pausedEvents : events;

    // Auto-scroll to top when new events arrive and not paused
    useEffect(() => {
        if (scrollRef.current && !isPaused) {
            scrollRef.current.scrollTop = 0;
        }
    }, [events, isPaused]);

    // Sound alert for HIGH/CRITICAL threats using Web Audio
    useEffect(() => {
        if (!soundEnabled || isPaused || events.length === 0) return;
        const latest = events[0];
        const scoreInfo = normalizeThreatScore(latest.threat_score);
        if (
            scoreInfo.severity === 'CRITICAL' ||
            scoreInfo.severity === 'HIGH' ||
            latest.threat_level === 'HIGH' ||
            latest.threat_level === 'CRITICAL' ||
            latest.attack_type === 'MALICIOUS'
        ) {
            playAlertBeep();
        }
    }, [events, soundEnabled, isPaused]);

    const getCountryFlag = useCallback((country) => {
        const flags = {
            'US': '🇺🇸', 'CN': '🇨🇳', 'RU': '🇷🇺', 'DE': '🇩🇪', 'FR': '🇫🇷',
            'IN': '🇮🇳', 'BR': '🇧🇷', 'JP': '🇯🇵', 'KR': '🇰🇷', 'GB': '🇬🇧',
        };
        return flags[country] || '🌐';
    }, []);

    return (
        <div className="event-stream-container">
            <div className="event-stream-header">
                <div className="header-left">
                    <h3>LIVE EVENT STREAM</h3>
                    <div className={`connection-dot ${isConnected ? 'connected' : 'disconnected'}`}>
                        {isConnected ? <Wifi size={12} /> : <WifiOff size={12} />}
                        <span>{isConnected ? 'CONNECTED' : 'DISCONNECTED'}</span>
                    </div>
                </div>
                <div className="header-controls">
                    <button
                        className={`ctrl-btn ${isPaused ? 'active' : ''}`}
                        onClick={() => {
                            if (!isPaused) {
                                setPausedEvents(events);
                            }
                            setIsPaused(!isPaused);
                        }}
                        title={isPaused ? 'Resume' : 'Pause'}
                    >
                        {isPaused ? <Play size={14} /> : <Pause size={14} />}
                    </button>
                    <button
                        className={`ctrl-btn ${!soundEnabled ? 'muted' : ''}`}
                        onClick={() => setSoundEnabled(!soundEnabled)}
                        title={soundEnabled ? 'Mute' : 'Unmute'}
                    >
                        {soundEnabled ? <Volume2 size={14} /> : <VolumeX size={14} />}
                    </button>
                    <div className="live-indicator">
                        <span className="pulse"></span> LIVE
                    </div>
                </div>
            </div>

            <div className="event-count-bar">
                <span>{displayEvents.length} events</span>
                {isPaused && <span className="paused-badge">⏸ PAUSED</span>}
            </div>

            <div className="event-list" ref={scrollRef}>
                {displayEvents.length === 0 ? (
                    <div className="empty-stream">
                        <div className="empty-icon">📡</div>
                        <div>Waiting for real-time telemetry...</div>
                        <div className="empty-sub">Events will appear as network packets are captured</div>
                    </div>
                ) : (
                    displayEvents.map((event, index) => {
                        const scoreInfo = normalizeThreatScore(event.threat_score);
                        return (
                            <div
                                key={event.id || index}
                                className={`event-item-wrapper ${selectedEvent === event ? 'expanded' : ''}`}
                                onClick={() => setSelectedEvent(selectedEvent === event ? null : event)}
                            >
                                <div className={`event-item ${scoreInfo.severityClass}`}>
                                    <div className="event-time">
                                        [{event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : '--:--:--'}]
                                    </div>
                                    <div className="event-details">
                                        <span className="event-ip">{event.src_ip || 'unknown'}</span>
                                        <span className="event-proto">{event.protocol || 'TCP'}</span>
                                        <span className="event-desc">{event.attack_type || 'TRAFFIC_TICK'}</span>
                                    </div>
                                    <div className="event-threat-badge">
                                        <span className={`badge ${scoreInfo.severityClass}`}>
                                            {scoreInfo.severity}
                                        </span>
                                    </div>
                                    <div className="event-score">
                                        {scoreInfo.percentageStr}
                                    </div>
                                </div>
                                {selectedEvent === event && (
                                    <div className={`event-expanded ${scoreInfo.severityClass}`}>
                                        <div className="exp-grid">
                                            <div className="exp-item">
                                                <label>SOURCE PORT:</label>
                                                <span>{event.src_port || 'ANY'}</span>
                                            </div>
                                            <div className="exp-item">
                                                <label>DEST IP:</label>
                                                <span>{event.dst_ip || 'Internal'}</span>
                                            </div>
                                            <div className="exp-item">
                                                <label>LENGTH:</label>
                                                <span>{event.length || 0} bytes</span>
                                            </div>
                                            <div className="exp-item">
                                                <label>COUNTRY:</label>
                                                <span>{getCountryFlag(event.country)} {event.country || 'Unknown'}</span>
                                            </div>
                                            <div className="exp-item">
                                                <label>THREAT LEVEL:</label>
                                                <span>{scoreInfo.severity}</span>
                                            </div>
                                            <div className="exp-item">
                                                <label>LOG ID:</label>
                                                <span>{event.id || 'LIVE_STREAM'}</span>
                                            </div>
                                        </div>
                                        <div className="exp-score-bar">
                                            <div className="score-fill" style={{ width: `${scoreInfo.percentage}%` }}></div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        );
                    })
                )}
            </div>
        </div>
    );
};

export default EventStream;

import React, { useEffect, useRef, useState, useCallback } from 'react';
import { useRealTime } from '../context/RealTimeContext';
import { Wifi, WifiOff, Volume2, VolumeX, Pause, Play } from 'lucide-react';
import './EventStream.css';

const EventStream = () => {
    const { events, isConnected } = useRealTime();
    const [selectedEvent, setSelectedEvent] = useState(null);
    const [soundEnabled, setSoundEnabled] = useState(true);
    const [isPaused, setIsPaused] = useState(false);
    const [pausedEvents, setPausedEvents] = useState([]);
    const scrollRef = useRef(null);
    const audioRef = useRef(null);

    const displayEvents = isPaused ? pausedEvents : events;

    // Auto-scroll to top on new event
    useEffect(() => {
        if (!isPaused && scrollRef.current) {
            scrollRef.current.scrollTop = 0;
        }
    }, [events, isPaused]);

    // Capture events when pausing
    useEffect(() => {
        if (isPaused) {
            setPausedEvents(events);
        }
    }, [isPaused]);

    // Sound alert for HIGH/CRITICAL threats
    useEffect(() => {
        if (!soundEnabled || isPaused || events.length === 0) return;
        const latest = events[0];
        if (
            latest.threat_level === 'HIGH' ||
            latest.threat_level === 'CRITICAL' ||
            latest.attack_type === 'MALICIOUS' ||
            (latest.threat_score && latest.threat_score > 75)
        ) {
            if (audioRef.current) {
                audioRef.current.play().catch(() => { });
            }
        }
    }, [events, soundEnabled, isPaused]);

    const getThreatClass = useCallback((event) => {
        const score = event.threat_score || 0;
        const level = event.threat_level || event.attack_type || 'BENIGN';
        if (level === 'CRITICAL' || level === 'MALICIOUS' || score > 80) return 'threat-critical';
        if (level === 'HIGH' || level === 'SUSPICIOUS' || score > 40) return 'threat-high';
        if (level === 'MEDIUM' || score > 20) return 'threat-medium';
        return 'threat-low';
    }, []);

    const getThreatLabel = useCallback((event) => {
        const score = event.threat_score || 0;
        if (score > 80) return 'CRITICAL';
        if (score > 60) return 'HIGH';
        if (score > 40) return 'MEDIUM';
        return 'LOW';
    }, []);

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
                        <span>{isConnected ? 'CONNECTED' : 'RECONNECTING'}</span>
                    </div>
                </div>
                <div className="header-controls">
                    <button
                        className={`ctrl-btn ${isPaused ? 'active' : ''}`}
                        onClick={() => setIsPaused(!isPaused)}
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

            <audio ref={audioRef} src="https://assets.mixkit.co/active_storage/sfx/2568/2568-preview.mp3" preload="auto" />

            <div className="event-list" ref={scrollRef}>
                {displayEvents.length === 0 ? (
                    <div className="empty-stream">
                        <div className="empty-icon">📡</div>
                        <div>Waiting for tactical data...</div>
                        <div className="empty-sub">Events will appear when threats are detected</div>
                    </div>
                ) : (
                    displayEvents.map((event, index) => (
                        <div
                            key={event.id || index}
                            className={`event-item-wrapper ${selectedEvent === event ? 'expanded' : ''}`}
                            onClick={() => setSelectedEvent(selectedEvent === event ? null : event)}
                        >
                            <div className={`event-item ${getThreatClass(event)}`}>
                                <div className="event-time">
                                    [{event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : '--:--:--'}]
                                </div>
                                <div className="event-details">
                                    <span className="event-ip">{event.src_ip || 'unknown'}</span>
                                    <span className="event-proto">{event.protocol || 'TCP'}</span>
                                    <span className="event-desc">{event.attack_type || 'TRAFFIC_TICK'}</span>
                                </div>
                                <div className="event-threat-badge">
                                    <span className={`badge ${getThreatClass(event)}`}>
                                        {getThreatLabel(event)}
                                    </span>
                                </div>
                                <div className="event-score">
                                    {Math.round(event.threat_score || 0)}%
                                </div>
                            </div>
                            {selectedEvent === event && (
                                <div className={`event-expanded ${getThreatClass(event)}`}>
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
                                            <span>{event.threat_level || 'LOW'}</span>
                                        </div>
                                        <div className="exp-item">
                                            <label>LOG ID:</label>
                                            <span>{event.id || 'LIVE_STREAM'}</span>
                                        </div>
                                    </div>
                                    <div className="exp-score-bar">
                                        <div className="score-fill" style={{ width: `${event.threat_score || 0}%` }}></div>
                                    </div>
                                </div>
                            )}
                        </div>
                    ))
                )}
            </div>
        </div>
    );
};

export default EventStream;

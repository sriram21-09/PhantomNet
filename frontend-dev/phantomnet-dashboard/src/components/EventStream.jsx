import React, { useEffect, useRef, useState } from 'react';
import { useRealTime } from '../context/RealTimeContext';
import './EventStream.css';

const EventStream = () => {
    const { events } = useRealTime();
    const [selectedEvent, setSelectedEvent] = useState(null);
    const scrollRef = useRef(null);
    const audioRef = useRef(null);

    // Auto-scroll to bottom on new event
    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = 0;
        }
    }, [events]);

    // Sound alert for HIGH threats
    useEffect(() => {
        if (events.length > 0) {
            const latest = events[0];
            if (latest.threat_level === 'HIGH' || latest.threat_level === 'CRITICAL' || latest.attack_type === 'MALICIOUS') {
                if (audioRef.current) {
                    audioRef.current.play().catch(e => console.log("Audio play blocked by browser"));
                }
            }
        }
    }, [events]);

    const getThreatClass = (event) => {
        const score = event.threat_score || 0;
        const level = event.threat_level || event.attack_type || 'BENIGN';

        if (level === 'CRITICAL' || level === 'MALICIOUS' || score > 80) return 'threat-critical';
        if (level === 'HIGH' || level === 'SUSPICIOUS' || score > 40) return 'threat-high';
        return 'threat-low';
    };

    return (
        <div className="event-stream-container">
            <div className="event-stream-header">
                <h3>LIVE EVENT STREAM</h3>
                <div className="live-indicator">
                    <span className="pulse"></span> LIVE
                </div>
            </div>

            <audio ref={audioRef} src="https://assets.mixkit.co/active_storage/sfx/2568/2568-preview.mp3" preload="auto" />

            <div className="event-list" ref={scrollRef}>
                {events.length === 0 ? (
                    <div className="empty-stream">Waiting for tactical data...</div>
                ) : (
                    events.map((event, index) => (
                        <div
                            key={index}
                            className={`event-item-wrapper ${selectedEvent === event ? 'expanded' : ''}`}
                            onClick={() => setSelectedEvent(selectedEvent === event ? null : event)}
                        >
                            <div className={`event-item ${getThreatClass(event)}`}>
                                <div className="event-time">[{new Date(event.timestamp).toLocaleTimeString()}]</div>
                                <div className="event-details">
                                    <span className="event-ip">{event.src_ip}</span>
                                    <span className="event-proto">{event.protocol}</span>
                                    <span className="event-desc">{event.attack_type || 'TRAFFIC_TICK'}</span>
                                </div>
                                <div className="event-score">
                                    {Math.round(event.threat_score)}%
                                </div>
                            </div>
                            {selectedEvent === event && (
                                <div className={`event-expanded ${getThreatClass(event)}`}>
                                    <div className="exp-grid">
                                        <div className="exp-item"><label>SOURCE PORT:</label> <span>{event.src_port || 'ANY'}</span></div>
                                        <div className="exp-item"><label>DEST IP:</label> <span>{event.dst_ip || 'Internal'}</span></div>
                                        <div className="exp-item"><label>LENGTH:</label> <span>{event.length || 0} bytes</span></div>
                                        <div className="exp-item"><label>LOG ID:</label> <span>{event.id || 'LIVE_STREAM'}</span></div>
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

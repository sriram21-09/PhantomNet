import React, { useState, useEffect } from 'react';
import AttackMap from '../components/AttackMap';
import '../Styles/pages/GeoDashboard.css';
import { FaChartBar, FaGlobeAmericas, FaFilter, FaHistory, FaDownload } from 'react-icons/fa';
import { toPng } from 'html-to-image';

const SAMPLE_ATTACKS = [
    { id: 1, source_ip: '103.25.46.2', source_country: 'Russia', source_lat: 55.75, source_lon: 37.61, dest_ip: '192.168.1.5', dest_region: 'US-East', dest_lat: 40.71, dest_lon: -74.00, severity: 'critical', timestamp: new Date().toISOString() },
    { id: 2, source_ip: '45.76.12.190', source_country: 'China', source_lat: 39.90, source_lon: 116.40, dest_ip: '172.16.0.4', dest_region: 'EU-West', dest_lat: 48.85, dest_lon: 2.35, severity: 'high', timestamp: new Date().toISOString() },
    { id: 3, source_ip: '185.12.34.56', source_country: 'France', source_lat: 48.85, source_lon: 2.35, dest_ip: '10.0.0.15', dest_region: 'Asia-South', dest_lat: 19.07, dest_lon: 72.87, severity: 'medium', timestamp: new Date().toISOString() },
    { id: 4, source_ip: '1.1.1.1', source_country: 'Australia', source_lat: -33.86, source_lon: 151.20, dest_ip: '192.168.10.1', dest_region: 'US-West', dest_lat: 34.05, dest_lon: -118.24, severity: 'low', timestamp: new Date().toISOString() }
];

const GeoDashboard = () => {
    const [attacks, setAttacks] = useState(SAMPLE_ATTACKS);
    const [timeFilter, setTimeFilter] = useState('Real-time');
    const [severityFilters, setSeverityFilters] = useState(['critical', 'high', 'medium', 'low']);

    const toggleSeverity = (severity) => {
        setSeverityFilters(prev =>
            prev.includes(severity)
                ? prev.filter(s => s !== severity)
                : [...prev, severity]
        );
    };

    const exportMap = async () => {
        const mapElement = document.querySelector('.leaflet-container');
        if (mapElement) {
            try {
                const dataUrl = await toPng(mapElement, {
                    cacheBust: true,
                    backgroundColor: '#020617'
                });
                const link = document.createElement('a');
                link.download = `phantomnet-geospatial-capture-${Date.now()}.png`;
                link.href = dataUrl;
                link.click();
            } catch (err) {
                console.error('Export failed:', err);
            }
        }
    };

    // Simulate incoming attacks
    useEffect(() => {
        const interval = setInterval(() => {
            const newAttack = {
                id: Date.now(),
                source_ip: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
                source_country: 'Unknown',
                source_lat: (Math.random() * 140) - 70,
                source_lon: (Math.random() * 360) - 180,
                dest_ip: '192.168.1.100',
                dest_region: 'Protected-Node',
                dest_lat: 37.77,
                dest_lon: -122.41,
                severity: ['critical', 'high', 'medium', 'low'][Math.floor(Math.random() * 4)],
                timestamp: new Date().toISOString()
            };
            setAttacks(prev => [newAttack, ...prev.slice(0, 19)]);
        }, 5000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="geo-dashboard-wrapper dashboard-wrapper">
            <div className="dashboard-header">
                <div className="header-content">
                    <div className="header-title">
                        <div className="dashboard-header-premium">
                            <div className="header-badge hud-font">GEO_INTEL_V.1</div>
                            <h1 className="dashboard-title glow-text">Geospatial Attack Intel</h1>
                            <p className="dashboard-subtitle text-dim">GLOBAL THREAT VECTOR VISUALIZATION | REAL-TIME ORIGIN TRACKING</p>
                        </div>
                    </div>
                    <div className="header-actions">
                        <button className="premium-btn primary hud-font" onClick={exportMap}>
                            <FaDownload /> EXPORT PNG
                        </button>
                    </div>
                </div>
            </div>

            <div className="geo-content-grid">
                {/* Sidebar Controls */}
                <div className="geo-sidebar">
                    <div className="geo-sidebar-card pro-card">
                        <div className="sidebar-header hud-font">
                            <FaFilter /> FILTERS
                        </div>
                        <div className="sidebar-section">
                            <label className="section-label">TIME SCALE</label>
                            <div className="filter-group">
                                {['Real-time', '1H', '24H', '7D'].map(t => (
                                    <button
                                        key={t}
                                        className={`filter-btn ${timeFilter === t ? 'active' : ''}`}
                                        onClick={() => setTimeFilter(t)}
                                    >
                                        {t}
                                    </button>
                                ))}
                            </div>
                        </div>
                        <div className="sidebar-section">
                            <label className="section-label">SEVERITY LEVELS</label>
                            <div className="severity-toggle-list">
                                {['critical', 'high', 'medium', 'low'].map(s => (
                                    <div
                                        key={s}
                                        className={`severity-toggle ${s} ${severityFilters.includes(s) ? 'active' : ''}`}
                                        onClick={() => toggleSeverity(s)}
                                    >
                                        <div className="toggle-dot"></div>
                                        <span>{s.toUpperCase()}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>

                    <div className="geo-sidebar-card pro-card live-feed">
                        <div className="sidebar-header hud-font">
                            <FaHistory /> RECENT ACTIVITY
                        </div>
                        <div className="feed-list no-scrollbar">
                            {attacks.map(attack => (
                                <div key={attack.id} className={`feed-item ${attack.severity}`}>
                                    <div className="feed-item-header">
                                        <span className="feed-ip">{attack.source_ip}</span>
                                        <span className="feed-time">{new Date(attack.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                                    </div>
                                    <div className="feed-item-detail">
                                        {attack.source_country} ➔ {attack.dest_region}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Main Map Area */}
                <div className="geo-main-view">
                    <AttackMap attacks={attacks} activeFilters={{ severity: severityFilters }} />

                    <div className="geo-stats-row">
                        <div className="geo-stat-mini pro-card">
                            <label>TOTAL HITS (24H)</label>
                            <div className="val">1,245,607</div>
                        </div>
                        <div className="geo-stat-mini pro-card">
                            <label>ACTIVE VECTORS</label>
                            <div className="val">{attacks.length}</div>
                        </div>
                        <div className="geo-stat-mini pro-card">
                            <label>TOP ORIGIN</label>
                            <div className="val">CHINA (CN)</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default GeoDashboard;

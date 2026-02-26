import React, { useEffect, useState } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import './GeoHeatmap.css';

const GeoHeatmap = () => {
    const [points, setPoints] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchHeatmapData = async () => {
            try {
                // Fetching from the general events API since it now has lat/lon
                const res = await fetch('/api/stats');
                const data = await res.json();

                // For demonstration/real-time, we might fetch recent events
                const eventsRes = await fetch('/analyze-traffic');
                const eventsData = await eventsRes.json();

                if (eventsData.status === "success") {
                    const validPoints = eventsData.data
                        .filter(e => e.packet_info.lat && e.packet_info.lon)
                        .map((e, idx) => ({
                            id: idx,
                            lat: e.packet_info.lat,
                            lon: e.packet_info.lon,
                            intensity: e.ai_analysis.threat_score,
                            ip: e.packet_info.src,
                            city: e.packet_info.city,
                            country: e.packet_info.location
                        }));
                    setPoints(validPoints);
                }
            } catch (err) {
                console.error("Heatmap fetch error:", err);
            } finally {
                setLoading(false);
            }
        };

        fetchHeatmapData();
        const interval = setInterval(fetchHeatmapData, 10000);
        return () => clearInterval(interval);
    }, []);

    if (loading) return <div className="heatmap-loading">Initializing Global Mesh...</div>;

    return (
        <div className="geo-heatmap-card pro-card">
            <h3 className="panel-title">Global Threat Mesh</h3>
            <div className="map-wrapper">
                <MapContainer
                    center={[20, 0]}
                    zoom={2}
                    style={{ height: '350px', width: '100%', borderRadius: '12px' }}
                    zoomControl={false}
                    attributionControl={false}
                >
                    <TileLayer
                        url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                    />
                    {points.map(point => (
                        <CircleMarker
                            key={point.id}
                            center={[point.lat, point.lon]}
                            radius={5 + (point.intensity * 10)}
                            fillColor={point.intensity > 0.7 ? '#ef4444' : '#f59e0b'}
                            color="none"
                            fillOpacity={0.6}
                        >
                            <Popup className="map-popup">
                                <div className="popup-content">
                                    <strong>{point.ip}</strong><br />
                                    {point.city}, {point.country}<br />
                                    Threat: {(point.intensity * 100).toFixed(1)}%
                                </div>
                            </Popup>
                        </CircleMarker>
                    ))}
                </MapContainer>
                <div className="map-overlay-vignette"></div>
            </div>
        </div>
    );
};

export default GeoHeatmap;

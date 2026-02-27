import React, { useEffect, useState, useMemo } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline, useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import '../Styles/components/AttackMap.css';

// Fix for default Leaflet marker icons in React
import icon from 'leaflet/dist/images/marker-icon.png';
import iconShadow from 'leaflet/dist/images/marker-shadow.png';

let DefaultIcon = L.icon({
    iconUrl: icon,
    shadowUrl: iconShadow,
    iconSize: [25, 41],
    iconAnchor: [12, 41]
});

L.Marker.prototype.options.icon = DefaultIcon;

// Custom pulsing icon generator
const createPulsingIcon = (severity) => {
    const color = severity === 'critical' ? '#ef4444' :
        severity === 'high' ? '#f97316' :
            severity === 'medium' ? '#eab308' : '#3b82f6';

    return L.divIcon({
        className: 'custom-pulsing-icon',
        html: `<div class="pulse-marker" style="--pulse-color: ${color}">
                <div class="pulse-ring"></div>
                <div class="pulse-center"></div>
               </div>`,
        iconSize: [20, 20],
        iconAnchor: [10, 10]
    });
};

// Component to handle map center/bounds updates
const ChangeView = ({ center, zoom }) => {
    const map = useMap();
    useEffect(() => {
        if (center) {
            map.setView(center, zoom);
        }
    }, [center, zoom, map]);
    return null;
};

const AttackMap = ({ attacks = [], activeFilters = {} }) => {
    const [mapCenter, setMapCenter] = useState([20, 0]);
    const [zoom, setZoom] = useState(2);

    // Filter attacks based on severity
    const filteredAttacks = useMemo(() => {
        return attacks.filter(attack => {
            if (activeFilters.severity && activeFilters.severity.length > 0) {
                return activeFilters.severity.includes(attack.severity);
            }
            return true;
        });
    }, [attacks, activeFilters]);

    // Dark Matter tiles from CartoDB provide a perfect NOC aesthetic
    const tileLayerUrl = "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png";
    const attribution = '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>';

    return (
        <div className="attack-map-container pro-card">
            <MapContainer
                center={mapCenter}
                zoom={zoom}
                scrollWheelZoom={true}
                className="leaflet-map-instance"
                style={{ height: '100%', width: '100%', background: '#020617' }}
            >
                <ChangeView center={mapCenter} zoom={zoom} />
                <TileLayer
                    url={tileLayerUrl}
                    attribution={attribution}
                />

                {filteredAttacks.map((attack, index) => (
                    <React.Fragment key={`${attack.id || index}`}>
                        {/* Source Marker */}
                        <Marker
                            position={[attack.source_lat, attack.source_lon]}
                            icon={createPulsingIcon(attack.severity)}
                        >
                            <Popup className="premium-popup">
                                <div className="popup-content hud-font">
                                    <h4 className={`severity-${attack.severity}`}>{attack.severity.toUpperCase()} ATTACK</h4>
                                    <p><strong>Source:</strong> {attack.source_ip}</p>
                                    <p><strong>Location:</strong> {attack.source_country}</p>
                                    <p><strong>Timestamp:</strong> {new Date(attack.timestamp).toLocaleTimeString()}</p>
                                </div>
                            </Popup>
                        </Marker>

                        {/* Destination Marker */}
                        <Marker
                            position={[attack.dest_lat, attack.dest_lon]}
                            icon={L.divIcon({
                                className: 'dest-marker',
                                html: '<div class="dest-dot"></div>',
                                iconSize: [10, 10]
                            })}
                        >
                            <Popup className="premium-popup">
                                <div className="popup-content hud-font">
                                    <h4>TARGET ASSET</h4>
                                    <p><strong>Target IP:</strong> {attack.dest_ip}</p>
                                    <p><strong>Region:</strong> {attack.dest_region}</p>
                                </div>
                            </Popup>
                        </Marker>

                        {/* Attack Vector Line */}
                        <Polyline
                            positions={[
                                [attack.source_lat, attack.source_lon],
                                [attack.dest_lat, attack.dest_lon]
                            ]}
                            pathOptions={{
                                color: attack.severity === 'critical' ? '#ef4444' : '#3b82f6',
                                weight: 1.5,
                                opacity: 0.4,
                                dashArray: '5, 10',
                                className: 'attack-line-animate'
                            }}
                        />
                    </React.Fragment>
                ))}
            </MapContainer>

            <div className="map-overlay-hud hud-font">
                <div className="status-indicator">
                    <span className="live-dot"></span>
                    GEOSPATIAL FEED ACTIVE
                </div>
            </div>
        </div>
    );
};

export default AttackMap;

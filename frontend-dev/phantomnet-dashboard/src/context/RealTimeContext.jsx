import React, { createContext, useContext, useEffect, useState, useRef } from 'react';

const RealTimeContext = createContext(null);

export const RealTimeProvider = ({ children }) => {
    const [events, setEvents] = useState([]);
    const [metrics, setMetrics] = useState(null);
    const [isConnected, setIsConnected] = useState(false);
    const ws = useRef(null);

    useEffect(() => {
        const connect = () => {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const host = window.location.hostname;
            const port = '8000'; // Assuming backend runs on 8000
            const wsUrl = `${protocol}//${host}:${port}/api/v1/realtime/ws`;

            ws.current = new WebSocket(wsUrl);

            ws.current.onopen = () => {
                console.log('✅ Real-time WebSocket connected');
                setIsConnected(true);
            };

            ws.current.onmessage = (event) => {
                const data = JSON.parse(event.data);
                if (data.type === 'EVENT_STREAM' || data.type === 'THREAT_ALERT') {
                    setEvents((prev) => [data.payload, ...prev].slice(0, 50));
                } else if (data.type === 'LIVE_METRICS') {
                    setMetrics(data.payload);
                }
            };

            ws.current.onclose = () => {
                console.log('❌ Real-time WebSocket disconnected. Retrying...');
                setIsConnected(false);
                setTimeout(connect, 3000); // Reconnect after 3s
            };

            ws.current.onerror = (err) => {
                console.error('WebSocket Error:', err);
                ws.current.close();
            };
        };

        connect();

        return () => {
            if (ws.current) ws.current.close();
        };
    }, []);

    return (
        <RealTimeContext.Provider value={{ events, metrics, isConnected }}>
            {children}
        </RealTimeContext.Provider>
    );
};

export const useRealTime = () => useContext(RealTimeContext);

import React, { createContext, useContext, useEffect, useState, useRef, useCallback } from 'react';

const RealTimeContext = createContext(null);

export const RealTimeProvider = ({ children }) => {
    const [events, setEvents] = useState([]);
    const [metrics, setMetrics] = useState(null);
    const [isConnected, setIsConnected] = useState(false);
    const [reconnectCount, setReconnectCount] = useState(0);
    const ws = useRef(null);
    const reconnectTimer = useRef(null);
    const connectRef = useRef(null);

    const connect = useCallback(() => {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/api/v1/realtime/ws`;

        try {
            ws.current = new WebSocket(wsUrl);

            ws.current.onopen = () => {
                setIsConnected(true);
                setReconnectCount(0);
            };

            ws.current.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    if (data.type === 'EVENT_STREAM' || data.type === 'THREAT_ALERT') {
                        setEvents((prev) => [data.payload, ...prev].slice(0, 50));
                    } else if (data.type === 'LIVE_METRICS') {
                        setMetrics(data.payload);
                    }
                } catch {
                    // Ignore JSON parse error
                }
            };

            ws.current.onclose = () => {
                setIsConnected(false);
                setReconnectCount(prev => prev + 1);
                reconnectTimer.current = setTimeout(() => {
                    if (connectRef.current) connectRef.current();
                }, 3000);
            };

            ws.current.onerror = () => {
                ws.current?.close();
            };
        } catch {
            setIsConnected(false);
            reconnectTimer.current = setTimeout(() => {
                if (connectRef.current) connectRef.current();
            }, 3000);
        }
    }, []);

    useEffect(() => {
        connectRef.current = connect;
    }, [connect]);

    useEffect(() => {
        // eslint-disable-next-line react-hooks/set-state-in-effect
        connect();

        return () => {
            if (ws.current) ws.current.close();
            if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
        };
    }, [connect]);

    return (
        <RealTimeContext.Provider value={{ events, metrics, isConnected, reconnectCount }}>
            {children}
        </RealTimeContext.Provider>
    );
};

// eslint-disable-next-line react-refresh/only-export-components
export const useRealTime = () => useContext(RealTimeContext);

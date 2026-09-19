import React, { createContext, useContext, useEffect, useState, useRef, useCallback } from 'react';

const RealTimeContext = createContext(null);

const BASE_DELAY = 1000;
const MAX_DELAY = 30000;
const BACKOFF_FACTOR = 2;

export const calculateBackoffWithJitter = (attempt, base = BASE_DELAY, max = MAX_DELAY, factor = BACKOFF_FACTOR) => {
    const expDelay = Math.min(max, base * Math.pow(factor, attempt));
    return Math.floor(Math.random() * expDelay);
};

export const RealTimeProvider = ({ children }) => {
    const [events, setEvents] = useState([]);
    const [metrics, setMetrics] = useState(null);
    const [isConnected, setIsConnected] = useState(false);
    const [reconnectCount, setReconnectCount] = useState(0);
    const ws = useRef(null);
    const reconnectTimer = useRef(null);
    const reconnectAttempts = useRef(0);
    const connectRef = useRef(null);

    const scheduleReconnect = useCallback(() => {
        if (reconnectTimer.current) {
            clearTimeout(reconnectTimer.current);
            reconnectTimer.current = null;
        }
        const delay = calculateBackoffWithJitter(reconnectAttempts.current);
        reconnectAttempts.current += 1;
        setReconnectCount(reconnectAttempts.current);
        reconnectTimer.current = setTimeout(() => {
            if (connectRef.current) connectRef.current();
        }, delay);
    }, []);

    const connect = useCallback(() => {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/api/v1/realtime/ws`;

        try {
            ws.current = new WebSocket(wsUrl);

            ws.current.onopen = () => {
                setIsConnected(true);
                reconnectAttempts.current = 0;
                setReconnectCount(0);
                if (reconnectTimer.current) {
                    clearTimeout(reconnectTimer.current);
                    reconnectTimer.current = null;
                }
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
                scheduleReconnect();
            };

            ws.current.onerror = () => {
                ws.current?.close();
            };
        } catch {
            setIsConnected(false);
            scheduleReconnect();
        }
    }, [scheduleReconnect]);

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

import React, { useState, useCallback, useEffect, useRef } from 'react';
import {
    ReactFlow,
    addEdge,
    Background,
    Controls,
    MiniMap,
    useNodesState,
    useEdgesState,
    Handle,
    Position,
    MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { toPng } from 'html-to-image';
import {
    FaDownload, FaExpand, FaServer, FaShieldAlt,
    FaUserSecret, FaWifi, FaEnvelope, FaGlobe, FaTimes, FaBolt, FaCheckCircle, FaExclamationTriangle
} from 'react-icons/fa';
import ThreatIntelWidget from './ThreatIntelWidget';
import './NetworkTopology.css';

// ─────────────────────────────────────────────
//  CUSTOM NODE COMPONENTS
// ─────────────────────────────────────────────

const StatusPulse = ({ color }) => (
    <span className="status-pulse" style={{ '--pulse-color': color }} />
);

const ControllerNode = ({ data, selected }) => {
    const isOnline = data?.status === 'online' || data?.status === 'active';

    return (
        <div 
            className={`pro-node node-controller ${selected ? 'node-selected' : ''} ${isOnline ? '' : 'node-inactive'}`}
            role="button"
            tabIndex={0}
            aria-label={`Core Controller: ${data?.label || 'PHANTOM_OS'}, Status: ${isOnline ? 'Online' : 'Offline'}`}
        >
            <Handle type="source" position={Position.Bottom} id="out" />
            <div className="node-glow-border controller-glow" />
            <div className="node-header">
                <div className="node-icon-wrap controller-icon">
                    <FaServer />
                </div>
                <div className="node-info">
                    <div className="node-label">{data?.label || 'PHANTOM_OS'}</div>
                    <div className="node-sublabel">{data?.sublabel || 'CORE CONTROL PLANE'}</div>
                </div>
                <StatusPulse color={isOnline ? '#3b82f6' : '#64748b'} />
            </div>
            <div className={`node-badge ${isOnline ? 'controller-badge' : 'inactive-badge'}`}>
                {isOnline ? 'ONLINE' : 'OFFLINE'}
            </div>
        </div>
    );
};

const HoneypotNode = ({ data, selected }) => {
    const iconMap = {
        SSH: <FaWifi />,
        HTTP: <FaGlobe />,
        FTP: <FaServer />,
        SMTP: <FaEnvelope />,
    };
    const icon = iconMap[data.label?.toUpperCase()] || <FaShieldAlt />;
    const isActive = data.status === 'active';
    const hostPort = data.external_port || data.port;
    const containerPort = data.internal_port || data.port;
    const hasPortMapping = hostPort && containerPort && hostPort !== containerPort;

    return (
        <div 
            className={`pro-node node-honeypot ${selected ? 'node-selected' : ''} ${isActive ? '' : 'node-inactive'}`}
            role="button"
            tabIndex={0}
            aria-label={`Honeypot: ${data.label}, Status: ${isActive ? 'Active' : 'Offline'}, Host Port: ${hostPort}, Container Port: ${containerPort}`}
        >
            <Handle type="target" position={Position.Top} id="in" />
            <Handle type="source" position={Position.Bottom} id="out" />
            <div className="node-glow-border honeypot-glow" />
            <div className="node-header">
                <div className="node-icon-wrap honeypot-icon">
                    {icon}
                </div>
                <div className="node-info">
                    <div className="node-label">{data.label?.toUpperCase() || 'HONEYPOT'}</div>
                    <div className="node-sublabel" title={`Host Port: ${hostPort} | Container: ${containerPort}`}>
                        {hasPortMapping ? `PORT ${hostPort} → ${containerPort}` : `PORT ${hostPort}`}
                    </div>
                </div>
                <StatusPulse color={isActive ? '#10b981' : '#64748b'} />
            </div>
            <div className={`node-badge ${isActive ? 'honeypot-badge' : 'inactive-badge'}`}>
                {isActive ? 'ACTIVE' : 'OFFLINE'}
            </div>
        </div>
    );
};

const AttackerNode = ({ data, selected }) => {
    const score = data.threat_score ?? 0;
    const danger = score > 70;

    return (
        <div 
            className={`pro-node node-attacker ${selected ? 'node-selected' : ''} ${danger ? 'node-danger-pulse' : ''}`}
            role="button"
            tabIndex={0}
            aria-label={`Attacker: ${data.ip}, Threat Score: ${score} percent, Attack Type: ${data.attack_type || 'Unknown'}`}
        >
            <Handle type="source" position={Position.Top} id="out" />
            <div className="node-glow-border attacker-glow" />
            <div className="node-header">
                <div className="node-icon-wrap attacker-icon">
                    <FaUserSecret />
                </div>
                <div className="node-info">
                    <div className="node-label">INTRUDER</div>
                    <div className="node-sublabel">{data.ip}</div>
                </div>
                {danger && <FaBolt className="danger-bolt" />}
            </div>
            <div className="threat-mini-bar">
                <div className="threat-mini-fill" style={{ width: `${score}%`, background: danger ? '#ef4444' : '#f59e0b' }} />
            </div>
            <div className="node-badge attacker-badge">{score}% THREAT</div>
        </div>
    );
};

const nodeTypes = {
    controller: ControllerNode,
    honeypot: HoneypotNode,
    attacker: AttackerNode,
};

// ─────────────────────────────────────────────
//  INITIAL STATE (Accurate Host & Container Ports)
// ─────────────────────────────────────────────

const INITIAL_NODES = [
    {
        id: 'controller',
        type: 'controller',
        position: { x: 475, y: 40 },
        data: {
            label: 'PHANTOM_OS',
            sublabel: 'CORE CONTROL PLANE',
            status: 'online',
            role: 'Central Control Plane',
        }
    },
    { 
        id: 'ssh', 
        type: 'honeypot', 
        position: { x: 100, y: 240 }, 
        data: { label: 'SSH', port: 2722, external_port: 2722, internal_port: 2222, status: 'active' } 
    },
    { 
        id: 'http', 
        type: 'honeypot', 
        position: { x: 350, y: 240 }, 
        data: { label: 'HTTP', port: 8080, external_port: 8080, internal_port: 8080, status: 'active' } 
    },
    { 
        id: 'ftp', 
        type: 'honeypot', 
        position: { x: 600, y: 240 }, 
        data: { label: 'FTP', port: 2721, external_port: 2721, internal_port: 2121, status: 'active' } 
    },
    { 
        id: 'smtp', 
        type: 'honeypot', 
        position: { x: 850, y: 240 }, 
        data: { label: 'SMTP', port: 2725, external_port: 2725, internal_port: 2525, status: 'active' } 
    },
];

const mkEdge = (src, tgt, opts = {}) => ({
    id: `e_${src}_${tgt}`,
    source: src, target: tgt,
    animated: true,
    markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f655' },
    style: { stroke: '#3b82f6', strokeWidth: 2, opacity: 0.7 },
    data: { type: 'logical_deception_link' },
    ...opts,
});

const INITIAL_EDGES = [
    mkEdge('controller', 'ssh'),
    mkEdge('controller', 'http'),
    mkEdge('controller', 'ftp'),
    mkEdge('controller', 'smtp'),
];

// ─────────────────────────────────────────────
//  MAIN COMPONENT
// ─────────────────────────────────────────────

const NetworkTopology = () => {
    const [nodes, setNodes, onNodesChange] = useNodesState(INITIAL_NODES);
    const [edges, setEdges, onEdgesChange] = useEdgesState(INITIAL_EDGES);
    const [selectedNode, setSelectedNode] = useState(null);
    const [isConnected, setIsConnected] = useState(false);
    const [attackCount, setAttackCount] = useState(0);
    const [trafficEventsCount, setTrafficEventsCount] = useState(0);
    const [syncState, setSyncState] = useState({
        status: 'synced', // 'synced' | 'degraded'
        lastSync: new Date(),
    });

    const flowRef = useRef(null);
    const reactFlowInstance = useRef(null);
    const ws = useRef(null);
    const nodesRef = useRef(nodes);
    const connectRef = useRef(null);

    useEffect(() => { nodesRef.current = nodes; }, [nodes]);

    useEffect(() => {
        const handleResize = () => {
            if (reactFlowInstance.current) {
                reactFlowInstance.current.fitView({ padding: 0.1 });
            }
        };
        window.addEventListener('resize', handleResize);
        return () => window.removeEventListener('resize', handleResize);
    }, []);

    const onConnect = useCallback(
        (params) => setEdges((eds) => addEdge({ ...params, animated: true }, eds)),
        [setEdges]
    );

    // ── Live Node Status Polling with Graceful Degradation Handling ───────────
    const fetchLiveHoneypots = useCallback(async () => {
        try {
            const res = await fetch('/api/honeypots');
            if (!res.ok) {
                setSyncState(prev => ({ ...prev, status: 'degraded' }));
                return;
            }
            const liveData = await res.json();
            
            setNodes(nds => nds.map(node => {
                if (node.type === 'honeypot') {
                    const match = liveData.find(d => d.name?.toUpperCase() === node.id?.toUpperCase());
                    if (match) {
                        return { 
                            ...node, 
                            data: { 
                                ...node.data, 
                                status: match.status, 
                                port: match.external_port || match.port,
                                external_port: match.external_port,
                                internal_port: match.internal_port,
                            } 
                        };
                    }
                } else if (node.type === 'controller') {
                    return {
                        ...node,
                        data: {
                            ...node.data,
                            status: isConnected ? 'online' : 'offline',
                        }
                    };
                }
                return node;
            }));

            setSyncState({
                status: 'synced',
                lastSync: new Date(),
            });
        } catch {
            setSyncState(prev => ({ ...prev, status: 'degraded' }));
        }
    }, [isConnected, setNodes]);

    useEffect(() => {
        fetchLiveHoneypots();
        const interval = setInterval(fetchLiveHoneypots, 5000);
        return () => clearInterval(interval);
    }, [fetchLiveHoneypots]);

    // ── WebSocket Connection & Event Stream ────────────────────────────
    const connectWS = useCallback(() => {
        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        ws.current = new WebSocket(`${proto}//${host}/api/v1/topology/ws`);

        ws.current.onopen = () => {
            setIsConnected(true);
            setNodes(nds => nds.map(node => {
                if (node.type === 'controller') {
                    return { ...node, data: { ...node.data, status: 'online' } };
                }
                return node;
            }));
        };

        ws.current.onclose = () => {
            setIsConnected(false);
            setNodes(nds => nds.map(node => {
                if (node.type === 'controller') {
                    return { ...node, data: { ...node.data, status: 'offline' } };
                }
                return node;
            }));
            setTimeout(() => {
                if (ws.current?.readyState === WebSocket.CLOSED) {
                    connectRef.current?.();
                }
            }, 5000);
        };

        ws.current.onerror = () => ws.current.close();

        ws.current.onmessage = (evt) => {
            try {
                const msg = JSON.parse(evt.data);
                if (msg.type === 'INIT' && msg.payload?.nodes) {
                    const validated = msg.payload.nodes.map(n => ({
                        ...n,
                        position: n.position || { x: Math.random() * 500, y: Math.random() * 400 }
                    }));
                    setNodes(validated);
                    setEdges(msg.payload.edges || []);
                    setSyncState({ status: 'synced', lastSync: new Date() });
                } else if (msg.type === 'THREAT_DETECTED' && msg.payload) {
                    const { attacker_ip, target_service, threat_score, attack_type } = msg.payload;
                    if (!attacker_ip) return;
                    const aid = `attacker_${attacker_ip.replace(/\./g, '_')}`;

                    setNodes(nds => {
                        if (nds.find(n => n.id === aid)) return nds;
                        setAttackCount(c => c + 1);
                        return [...nds, {
                            id: aid, type: 'attacker',
                            position: { x: 100 + Math.random() * 600, y: 440 },
                            data: { ip: attacker_ip, threat_score, attack_type }
                        }];
                    });

                    setEdges(eds => {
                        const eid = `e_attack_${aid}`;
                        if (eds.find(e => e.id === eid)) return eds;
                        const targetNode = nodesRef.current.find(n =>
                            n.data?.external_port === target_service ||
                            n.data?.internal_port === target_service ||
                            n.data?.port === target_service ||
                            n.id === target_service?.toString().toLowerCase()
                        );
                        const targetId = targetNode?.id || 'ssh';
                        return [...eds, {
                            id: eid, source: aid, target: targetId,
                            animated: true,
                            style: { stroke: '#ef4444', strokeWidth: 3 },
                            markerEnd: { type: MarkerType.ArrowClosed, color: '#ef4444' },
                            className: 'attack-edge',
                        }];
                    });
                } else if (msg.type === 'TRAFFIC_TICK') {
                    setTrafficEventsCount(prev => prev + (msg.payload?.count || 1));
                }
            } catch {
                // Ignore parse error
            }
        };
    }, [setEdges, setNodes]);

    useEffect(() => {
        connectRef.current = connectWS;
        connectWS();
        return () => {
            if (ws.current) { ws.current.onclose = null; ws.current.close(); }
        };
    }, [connectWS]);

    // ── Actions ──────────────────────────────
    const onNodeClick = (_, node) => setSelectedNode(node);

    const clearAttackers = () => {
        setNodes(nds => nds.filter(n => n.type !== 'attacker'));
        setEdges(eds => eds.filter(e => !e.id.startsWith('e_attack')));
        setAttackCount(0);
        setSelectedNode(null);
    };

    const resetTopology = () => {
        setNodes(INITIAL_NODES);
        setEdges(INITIAL_EDGES);
        setAttackCount(0);
        setSelectedNode(null);
        setTimeout(() => {
            reactFlowInstance.current?.fitView({ padding: 0.1 });
        }, 50);
    };

    const downloadImage = () => {
        if (!flowRef.current) return;
        toPng(flowRef.current, {
            filter: (el) => {
                const excluded = ['react-flow__controls', 'react-flow__minimap', 'topology-controls', 'node-details-panel', 'reconnect-overlay'];
                return !excluded.some(cls => el?.classList?.contains(cls));
            },
            backgroundColor: '#0b0f19',
            pixelRatio: 2,
        }).then(url => {
            const a = document.createElement('a');
            a.download = `phantomnet-topology-${new Date().toISOString().split('T')[0]}.png`;
            a.href = url;
            a.click();
        });
    };

    // ── Node Details Panel ───────────────────
    const renderDetailsPanel = () => {
        if (!selectedNode) return null;
        const n = selectedNode;
        const isAttacker = n.type === 'attacker';
        const isController = n.type === 'controller';
        const score = n.data?.threat_score ?? 0;
        const hostPort = n.data?.external_port || n.data?.port;
        const containerPort = n.data?.internal_port || n.data?.port;

        return (
            <div className="node-details-panel" role="region" aria-label="Node Details">
                <div className="details-header">
                    <div className={`details-type-badge ${n.type}-badge-header`}>
                        {n.type?.toUpperCase()}
                    </div>
                    <button 
                        className="close-btn" 
                        onClick={() => setSelectedNode(null)} 
                        aria-label="Close details panel"
                    >
                        <FaTimes />
                    </button>
                </div>

                <div className="details-title">{n.data?.ip || n.data?.label || n.id}</div>

                <div className="detail-grid">
                    <div className="detail-cell">
                        <span className="detail-label">NODE ID</span>
                        <span className="detail-value mono">{n.id}</span>
                    </div>
                    <div className="detail-cell">
                        <span className="detail-label">TYPE</span>
                        <span className="detail-value">{n.type?.toUpperCase()}</span>
                    </div>

                    {isController && (
                        <div className="detail-cell span2">
                            <span className="detail-label">ARCHITECTURE ROLE</span>
                            <span className="detail-value text-blue">{n.data?.role || 'Core Control Plane'}</span>
                        </div>
                    )}

                    {hostPort && (
                        <div className="detail-cell">
                            <span className="detail-label">HOST PORT (EXTERNAL)</span>
                            <span className="detail-value mono">{hostPort}</span>
                        </div>
                    )}
                    {containerPort && (
                        <div className="detail-cell">
                            <span className="detail-label">CONTAINER PORT (INTERNAL)</span>
                            <span className="detail-value mono">{containerPort}</span>
                        </div>
                    )}

                    {n.data?.status && (
                        <div className="detail-cell">
                            <span className="detail-label">OPERATIONAL STATUS</span>
                            <span className={`detail-value ${n.data.status === 'active' || n.data.status === 'online' ? 'text-green' : 'text-red'}`}>
                                {n.data.status?.toUpperCase()}
                            </span>
                        </div>
                    )}

                    <div className="detail-cell span2">
                        <span className="detail-label">TOPOLOGY RELATION</span>
                        <span className="detail-value text-dim">
                            {isController ? 'Orchestration Hub' : isAttacker ? 'Inbound Threat Actor' : 'Logical Deception Endpoint'}
                        </span>
                    </div>

                    {isAttacker && (
                        <div className="detail-cell span2">
                            <span className="detail-label">THREAT SCORE</span>
                            <div className="threat-bar-wrap">
                                <div className="threat-bar-track">
                                    <div
                                        className="threat-bar-fill"
                                        style={{
                                            width: `${score}%`,
                                            background: score > 70 ? 'linear-gradient(90deg,#ef4444,#dc2626)' : 'linear-gradient(90deg,#f59e0b,#d97706)'
                                        }}
                                    />
                                </div>
                                <span className="threat-bar-label" style={{ color: score > 70 ? '#ef4444' : '#f59e0b' }}>
                                    {score}%
                                </span>
                            </div>
                        </div>
                    )}
                    {n.data?.attack_type && (
                        <div className="detail-cell span2">
                            <span className="detail-label">ATTACK TYPE</span>
                            <span className="detail-value text-red">{n.data.attack_type}</span>
                        </div>
                    )}
                </div>

                {isAttacker && n.data?.ip && (
                    <div className="intel-section">
                        <div className="intel-section-label">⚡ LIVE THREAT INTEL</div>
                        <div className="mini-intel-container">
                            <ThreatIntelWidget ip={n.data.ip} />
                        </div>
                    </div>
                )}

                <button className="control-btn full-btn" onClick={() => setSelectedNode(null)}>
                    Close Panel
                </button>
            </div>
        );
    };

    // ─────────────────────────────────────────
    return (
        <div className="topology-container" ref={flowRef}>
            {/* Screen Reader Accessible Live Summary */}
            <div className="sr-only" aria-live="polite">
                <h4>Network Topology Accessibility Summary</h4>
                <p>Central Control Plane: PHANTOM_OS, Status: {isConnected ? 'Online' : 'Offline'}.</p>
                <ul>
                    {nodes.filter(n => n.type === 'honeypot').map(n => (
                        <li key={n.id}>
                            Decoy {n.data?.label}: Host port {n.data?.external_port || n.data?.port}, Status: {n.data?.status}.
                        </li>
                    ))}
                    {nodes.filter(n => n.type === 'attacker').map(n => (
                        <li key={n.id}>
                            Attacker IP {n.data?.ip}, Threat Score: {n.data?.threat_score}%.
                        </li>
                    ))}
                </ul>
            </div>

            {/* Header */}
            <div className="topology-header">
                <div className="topo-title-row">
                    <h3 className="topo-title">Logical Deception Infrastructure</h3>
                    <span className="topo-badge">LOGICAL TOPOLOGY</span>
                </div>
                <div className="topo-subtitle">
                    Distributed Decoy Nodes Orchestrated by PhantomNet Core Control Plane
                </div>
                <div className="topo-status-row">
                    <span className={`live-dot ${isConnected ? 'dot-live' : 'dot-offline'}`} />
                    <span className="live-label">
                        {isConnected ? 'LIVE FEED ACTIVE' : 'CONNECTING...'}
                    </span>
                    <span className={`sync-pill ${syncState.status === 'synced' ? 'sync-ok' : 'sync-degraded'}`}>
                        {syncState.status === 'synced' ? (
                            <><FaCheckCircle /> Synced {syncState.lastSync.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</>
                        ) : (
                            <><FaExclamationTriangle /> Sync Degraded</>
                        )}
                    </span>
                    {trafficEventsCount > 0 && (
                        <span className="traffic-counter" title="Analyzed traffic ticks">
                            ⚡ {trafficEventsCount} EVENTS
                        </span>
                    )}
                    {attackCount > 0 && (
                        <span className="attack-counter">⚠ {attackCount} ACTIVE THREAT{attackCount > 1 ? 'S' : ''}</span>
                    )}
                </div>
            </div>

            {/* WS Reconnect Overlay */}
            {!isConnected && (
                <div className="reconnect-overlay">
                    <div className="reconnect-spinner" />
                    <div className="reconnect-text">Establishing Secure Link...</div>
                    <div className="reconnect-sub">WebSocket handshake in progress</div>
                </div>
            )}

            {/* React Flow Canvas */}
            <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onConnect={onConnect}
                onNodeClick={onNodeClick}
                nodeTypes={nodeTypes}
                onInit={(instance) => {
                    reactFlowInstance.current = instance;
                    instance.fitView({ padding: 0.1 });
                }}
                fitView
                fitViewOptions={{ padding: 0.1 }}
                proOptions={{ hideAttribution: true }}
            >
                <Background color="#1e3a5f" gap={24} size={1} variant="dots" />
                <Controls className="topo-controls-bar" />
                <MiniMap
                    nodeColor={(n) => n.type === 'attacker' ? '#ef4444' : n.type === 'honeypot' ? '#10b981' : '#3b82f6'}
                    style={{ background: 'rgba(10,14,30,0.9)', border: '1px solid rgba(59,130,246,0.2)', borderRadius: '10px' }}
                    maskColor="rgba(0,0,0,0.5)"
                />
            </ReactFlow>

            {/* Selected Node Panel */}
            {renderDetailsPanel()}

            {/* Bottom Control Bar */}
            <div className="topology-controls">
                <button className="control-btn danger-btn" onClick={clearAttackers} title="Remove all attacker nodes">
                    🧹 Clear Threats
                </button>
                <button className="control-btn" onClick={resetTopology} title="Reset to default topology">
                    <FaExpand /> Reset
                </button>
                <button className="control-btn export-btn" onClick={downloadImage} title="Export topology as PNG">
                    <FaDownload /> Export PNG
                </button>
            </div>
        </div>
    );
};

export default NetworkTopology;


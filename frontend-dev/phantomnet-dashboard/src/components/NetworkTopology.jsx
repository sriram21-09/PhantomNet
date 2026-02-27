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
    FaUserSecret, FaWifi, FaEnvelope, FaGlobe, FaTimes, FaBolt
} from 'react-icons/fa';
import ThreatIntelWidget from './ThreatIntelWidget';
import './NetworkTopology.css';

// ─────────────────────────────────────────────
//  CUSTOM NODE COMPONENTS
// ─────────────────────────────────────────────

const StatusPulse = ({ color }) => (
    <span className="status-pulse" style={{ '--pulse-color': color }} />
);

const ControllerNode = ({ data, selected }) => (
    <div className={`pro-node node-controller ${selected ? 'node-selected' : ''}`}>
        <Handle type="source" position={Position.Bottom} id="out" />
        <div className="node-glow-border controller-glow" />
        <div className="node-header">
            <div className="node-icon-wrap controller-icon">
                <FaServer />
            </div>
            <div className="node-info">
                <div className="node-label">PHANTOM_OS</div>
                <div className="node-sublabel">CORE CONTROLLER</div>
            </div>
            <StatusPulse color="#3b82f6" />
        </div>
        <div className="node-badge controller-badge">ONLINE</div>
    </div>
);

const HoneypotNode = ({ data, selected }) => {
    const iconMap = {
        SSH: <FaWifi />,
        HTTP: <FaGlobe />,
        FTP: <FaServer />,
        SMTP: <FaEnvelope />,
    };
    const icon = iconMap[data.label?.toUpperCase()] || <FaShieldAlt />;
    const isActive = data.status === 'active';

    return (
        <div className={`pro-node node-honeypot ${selected ? 'node-selected' : ''} ${isActive ? '' : 'node-inactive'}`}>
            <Handle type="target" position={Position.Top} id="in" />
            <Handle type="source" position={Position.Bottom} id="out" />
            <div className="node-glow-border honeypot-glow" />
            <div className="node-header">
                <div className="node-icon-wrap honeypot-icon">
                    {icon}
                </div>
                <div className="node-info">
                    <div className="node-label">{data.label?.toUpperCase() || 'HONEYPOT'}</div>
                    <div className="node-sublabel">PORT {data.port}</div>
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
        <div className={`pro-node node-attacker ${selected ? 'node-selected' : ''} ${danger ? 'node-danger-pulse' : ''}`}>
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
//  INITIAL STATE
// ─────────────────────────────────────────────

const INITIAL_NODES = [
    {
        id: 'controller',
        type: 'controller',
        position: { x: 475, y: 40 },
        data: { label: 'Controller' }
    },
    { id: 'ssh', type: 'honeypot', position: { x: 100, y: 240 }, data: { label: 'SSH', port: 2222, status: 'active' } },
    { id: 'http', type: 'honeypot', position: { x: 350, y: 240 }, data: { label: 'HTTP', port: 8080, status: 'active' } },
    { id: 'ftp', type: 'honeypot', position: { x: 600, y: 240 }, data: { label: 'FTP', port: 2121, status: 'active' } },
    { id: 'smtp', type: 'honeypot', position: { x: 850, y: 240 }, data: { label: 'SMTP', port: 2525, status: 'active' } },
];

const mkEdge = (src, tgt, opts = {}) => ({
    id: `e_${src}_${tgt}`,
    source: src, target: tgt,
    animated: true,
    markerEnd: { type: MarkerType.ArrowClosed, color: '#3b82f655' },
    style: { stroke: '#3b82f6', strokeWidth: 2, opacity: 0.7 },
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

    const flowRef = useRef(null);
    const ws = useRef(null);
    const nodesRef = useRef(nodes);

    useEffect(() => { nodesRef.current = nodes; }, [nodes]);

    const onConnect = useCallback(
        (params) => setEdges((eds) => addEdge({ ...params, animated: true }, eds)),
        [setEdges]
    );

    // ── WebSocket ────────────────────────────
    const connectWS = useCallback(() => {
        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const isLocal = ['localhost', '127.0.0.1', '[::1]'].includes(window.location.hostname);
        const host = isLocal ? '127.0.0.1:8000' : window.location.host;
        ws.current = new WebSocket(`${proto}//${host}/api/v1/topology/ws`);

        ws.current.onopen = () => setIsConnected(true);
        ws.current.onclose = () => {
            setIsConnected(false);
            setTimeout(connectWS, 5000);
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
                            n.data?.port === target_service || n.id === target_service?.toLowerCase()
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
                    setEdges(eds => eds.map(e => ({ ...e, animated: true })));
                }
            } catch (err) { console.error('[Topology] WS parse error:', err); }
        };
    }, [setEdges, setNodes]);

    useEffect(() => {
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
        const score = n.data?.threat_score ?? 0;

        return (
            <div className="node-details-panel">
                <div className="details-header">
                    <div className={`details-type-badge ${n.type}-badge-header`}>
                        {n.type?.toUpperCase()}
                    </div>
                    <button className="close-btn" onClick={() => setSelectedNode(null)}>
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
                    {n.data?.port && (
                        <div className="detail-cell">
                            <span className="detail-label">PORT</span>
                            <span className="detail-value mono">{n.data.port}</span>
                        </div>
                    )}
                    {n.data?.status && (
                        <div className="detail-cell">
                            <span className="detail-label">STATUS</span>
                            <span className={`detail-value ${n.data.status === 'active' ? 'text-green' : 'text-red'}`}>
                                {n.data.status?.toUpperCase()}
                            </span>
                        </div>
                    )}
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
            {/* Header */}
            <div className="topology-header">
                <div className="topo-title-row">
                    <div className="topo-badge hud-font">NODE_DELTA</div>
                    <h3 className="topo-title">Network Infrastructure Topology</h3>
                </div>
                <div className="topo-status-row">
                    <span className={`live-dot ${isConnected ? 'dot-live' : 'dot-offline'}`} />
                    <span className="live-label">{isConnected ? 'LIVE FEED ACTIVE' : 'CONNECTING...'}</span>
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
                fitView
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

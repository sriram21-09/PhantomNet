import React, { useState, useCallback, useEffect, useRef } from 'react';
import {
    ReactFlow,
    addEdge,
    Background,
    Controls,
    useNodesState,
    useEdgesState,
    Handle,
    Position
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { toPng } from 'html-to-image';
import { FaDownload, FaExpand, FaServer, FaShieldAlt, FaUserSecret } from 'react-icons/fa';
import ThreatIntelWidget from './ThreatIntelWidget';
import './NetworkTopology.css';

// --- Custom Node Components ---

const ControllerNode = ({ data }) => (
    <div className="pro-node node-controller">
        <Handle type="source" position={Position.Bottom} />
        <div className="node-header">
            <FaServer className="node-icon" />
            <div className="node-info">
                <div className="node-label">PHANTOM_OS</div>
                <div className="node-port">CORE CONTROLLER</div>
            </div>
        </div>
    </div>
);

const HoneypotNode = ({ data }) => (
    <div className="pro-node node-honeypot">
        <Handle type="target" position={Position.Top} />
        <Handle type="source" position={Position.Bottom} />
        <div className="node-header">
            <FaShieldAlt className="node-icon" style={{ color: '#10b981' }} />
            <div className="node-info">
                <div className="node-label">{data.label}</div>
                <div className="node-port">PORT {data.port}</div>
            </div>
        </div>
    </div>
);

const AttackerNode = ({ data }) => (
    <div className="pro-node node-attacker">
        <Handle type="source" position={Position.Top} />
        <div className="node-header">
            <FaUserSecret className="node-icon" style={{ color: '#ef4444' }} />
            <div className="node-info">
                <div className="node-label">INTRUDER</div>
                <div className="node-port">{data.ip}</div>
            </div>
        </div>
    </div>
);

const nodeTypes = {
    controller: ControllerNode,
    honeypot: HoneypotNode,
    attacker: AttackerNode,
};

// --- Main Component ---

const initialNodes = [
    {
        id: 'controller',
        type: 'controller',
        position: { x: 400, y: 50 },
        data: { label: 'Controller' }
    },
    {
        id: 'ssh',
        type: 'honeypot',
        position: { x: 200, y: 250 },
        data: { label: 'SSH', port: 2222 }
    },
    {
        id: 'http',
        type: 'honeypot',
        position: { x: 600, y: 250 },
        data: { label: 'HTTP', port: 8080 }
    },
];

const initialEdges = [
    { id: 'e1-2', source: 'controller', target: 'ssh', animated: true },
    { id: 'e1-3', source: 'controller', target: 'http', animated: true },
];

const NetworkTopology = () => {
    const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
    const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
    const [selectedNode, setSelectedNode] = useState(null);
    const [isConnected, setIsConnected] = useState(false);

    const reactFlowWrapper = useRef(null);
    const ws = useRef(null);
    const nodesRef = useRef(nodes);

    // Keep nodesRef in sync
    useEffect(() => {
        nodesRef.current = nodes;
    }, [nodes]);

    const onConnect = useCallback((params) => setEdges((eds) => addEdge(params, eds)), [setEdges]);

    // WebSocket Integration with Reconnect Logic
    const connectWS = useCallback(() => {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        // Always target port 8000 for backend API if on localhost/127.0.0.1
        const isLocal = ['localhost', '127.0.0.1', '[::1]'].includes(window.location.hostname);
        const host = isLocal ? '127.0.0.1:8000' : window.location.host;

        console.log(`[Topology] Connecting to WS: ${protocol}//${host}/api/v1/topology/ws`);
        ws.current = new WebSocket(`${protocol}//${host}/api/v1/topology/ws`);

        ws.current.onopen = () => {
            setIsConnected(true);
            console.log('[Topology] WS Connected');
        };

        ws.current.onclose = () => {
            setIsConnected(false);
            console.log('[Topology] WS Disconnected. Retrying in 5s...');
            setTimeout(connectWS, 5000);
        };

        ws.current.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);

                if (message.type === 'INIT' && message.payload?.nodes) {
                    // Safety: Ensure all nodes have the required 'position' property
                    const validatedNodes = message.payload.nodes.map(node => ({
                        ...node,
                        position: node.position || { x: Math.random() * 400, y: Math.random() * 400 }
                    }));
                    setNodes(validatedNodes);
                    setEdges(message.payload.edges || []);
                } else if (message.type === 'THREAT_DETECTED' && message.payload) {
                    const { attacker_ip, target_service, threat_score, attack_type } = message.payload;
                    if (!attacker_ip) return;

                    const attackerId = `attacker_${attacker_ip.replace(/\./g, '_')}`;

                    setNodes(nds => {
                        if (nds.find(n => n.id === attackerId)) return nds;
                        return [
                            ...nds,
                            {
                                id: attackerId,
                                type: 'attacker',
                                position: { x: Math.random() * 400 + 200, y: 500 },
                                data: { ip: attacker_ip, threat_score, attack_type }
                            }
                        ];
                    });

                    setEdges(eds => {
                        const edgeId = `e_attack_${attackerId}`;
                        if (eds.find(e => e.id === edgeId)) return eds;

                        const targetNode = nodesRef.current.find(n => n.data?.port === target_service);
                        const targetId = targetNode ? targetNode.id : 'ssh_honeypot';

                        return [
                            ...eds,
                            {
                                id: edgeId,
                                source: attackerId,
                                target: targetId,
                                animated: true,
                                style: { stroke: '#ef4444', strokeWidth: 3 },
                                className: 'active'
                            }
                        ];
                    });
                } else if (message.type === 'TRAFFIC_TICK') {
                    setEdges(eds => eds.map(e => ({ ...e, animated: true })));
                    setTimeout(() => {
                        setEdges(eds => eds.map(e => ({ ...e, animated: false })));
                    }, 1500);
                }
            } catch (err) {
                console.error('[Topology] Message processing error:', err);
            }
        };
    }, [setEdges, setNodes]);

    useEffect(() => {
        connectWS();
        return () => {
            if (ws.current) {
                ws.current.onclose = null; // Prevent reconnect on unmount
                ws.current.close();
            }
        };
    }, [connectWS]);

    const onNodeClick = (_, node) => {
        setSelectedNode(node);
    };

    const clearAttackers = () => {
        setNodes(nds => nds.filter(n => n.type !== 'attacker'));
        setEdges(eds => eds.filter(e => !e.id.startsWith('e_attack')));
    };

    const downloadImage = () => {
        if (reactFlowWrapper.current === null) return;

        toPng(reactFlowWrapper.current, {
            filter: (node) => {
                const excludedClasses = ['react-flow__controls', 'topology-controls', 'node-details-panel', 'reconnect-overlay'];
                return !excludedClasses.some(cls => node?.classList?.contains(cls));
            },
            backgroundColor: '#0b0f19',
        }).then((dataUrl) => {
            const link = document.createElement('a');
            link.download = `phantomnet-topology-${new Date().toISOString().split('T')[0]}.png`;
            link.href = dataUrl;
            link.click();
        });
    };

    return (
        <div className="topology-container" ref={reactFlowWrapper}>
            <div className="topology-header">
                <h3>Network Infrastructure Topology</h3>
                <div style={{ color: isConnected ? '#10b981' : '#ef4444', fontSize: '0.75rem', marginTop: '4px', fontWeight: 'bold' }}>
                    {isConnected ? '● LIVE FEED ACTIVE' : '○ CONNECTING TO SENSORS...'}
                </div>
            </div>

            {!isConnected && (
                <div className="reconnect-overlay">
                    <div className="reconnect-spinner"></div>
                    <div style={{ color: '#fff', fontSize: '0.9rem' }}>Establishing Secure Link...</div>
                </div>
            )}

            <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onConnect={onConnect}
                onNodeClick={onNodeClick}
                nodeTypes={nodeTypes}
                fitView
            >
                <Background color="#1e293b" gap={20} variant="dots" />
                <Controls />
            </ReactFlow>

            {selectedNode && (
                <div className="node-details-panel">
                    <div className="details-header">
                        <h4>Node Details</h4>
                        <button className="close-btn" onClick={() => setSelectedNode(null)}>✕</button>
                    </div>
                    <div className="detail-row">
                        <span className="detail-label">ID</span>
                        <span className="detail-value">{selectedNode.id}</span>
                    </div>
                    <div className="detail-row">
                        <span className="detail-label">Type</span>
                        <span className="detail-value" style={{ textTransform: 'uppercase' }}>{selectedNode.type}</span>
                    </div>
                    {selectedNode.data.ip && (
                        <div className="detail-row">
                            <span className="detail-label">IP Address</span>
                            <span className="detail-value">{selectedNode.data.ip}</span>
                        </div>
                    )}
                    {selectedNode.data.port && (
                        <div className="detail-row">
                            <span className="detail-label">Port</span>
                            <span className="detail-value">{selectedNode.data.port}</span>
                        </div>
                    )}
                    {selectedNode.data.threat_score !== undefined && (
                        <div className="detail-row">
                            <span className="detail-label">Threat Score</span>
                            <span className="detail-value" style={{ color: selectedNode.data.threat_score > 70 ? '#ef4444' : '#fbbf24' }}>
                                {selectedNode.data.threat_score}%
                            </span>
                        </div>
                    )}

                    {/* Pro Integration: Live Threat Intel */}
                    {selectedNode.type === 'attacker' && selectedNode.data.ip && (
                        <div style={{ marginTop: '20px', borderTop: '1px solid rgba(255,255,255,0.1)', paddingTop: '16px' }}>
                            <div className="detail-label" style={{ marginBottom: '12px', fontSize: '0.75rem', fontWeight: 'bold', color: '#3b82f6' }}>
                                LIVE THREAT INTELLIGENCE
                            </div>
                            <div className="mini-intel-container">
                                <ThreatIntelWidget ip={selectedNode.data.ip} />
                            </div>
                        </div>
                    )}

                    <div style={{ marginTop: '24px' }}>
                        <button className="control-btn" style={{ width: '100%', justifyContent: 'center' }} onClick={() => setSelectedNode(null)}>
                            Close Details
                        </button>
                    </div>
                </div>
            )}

            <div className="topology-controls">
                <button className="control-btn" onClick={clearAttackers}>
                    🧹 Clear Attackers
                </button>
                <button className="control-btn" onClick={() => { setNodes(initialNodes); setEdges(initialEdges); }}>
                    <FaExpand /> Reset
                </button>
                <button className="control-btn" onClick={downloadImage}>
                    <FaDownload /> Export PNG
                </button>
            </div>
        </div>
    );
};

export default NetworkTopology;

import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
    Search, Shield, Activity, Briefcase, Database, Download,
    TriangleAlert, RefreshCw, Target, Crosshair, Layers, Zap
} from 'lucide-react';
import QueryBuilder from '../components/hunting/QueryBuilder';
import EventTimeline from '../components/hunting/EventTimeline';
import CaseManagement from '../components/hunting/CaseManagement';
import { useRealTime } from '../context/RealTimeContext';
import { exportToCSV, exportToJSON } from '../utils/exportUtils';
import { generatePDF } from '../utils/exportPDF';
import './ThreatHunting.css';

const API_BASE = '/api/v1';

const formatThreatScore = (score) => {
    if (score === null || score === undefined) return 0;
    const num = typeof score === 'number' ? score : parseFloat(score) || 0;
    return Math.round(num <= 1.0 ? num * 100 : num);
};

const ThreatHunting = () => {
    const { events: liveEvents, isConnected } = useRealTime();
    const [results, setResults] = useState([]);
    const [loading, setLoading] = useState(false);
    const [selectedEvent, setSelectedEvent] = useState(null);
    const [cases, setCases] = useState([]);
    const [queryStats, setQueryStats] = useState(null);
    const [activeTab, setActiveTab] = useState('timeline'); // 'timeline' | 'correlation'
    const [correlationData, setCorrelationData] = useState([]);
    const [loadingCorrelation, setLoadingCorrelation] = useState(false);
    const [exportStatus, setExportStatus] = useState('');
    const [searchError, setSearchError] = useState(null);
    const [lastQuery, setLastQuery] = useState(null);

    // Real-Time Streaming State
    const [liveMode, setLiveMode] = useState(true);
    const [autoStream, setAutoStream] = useState(true);
    const [unreadLiveCount, setUnreadLiveCount] = useState(0);
    const [liveBuffer, setLiveBuffer] = useState([]);

    const handleSearch = async (query) => {
        setLoading(true);
        setSelectedEvent(null);
        setQueryStats(null);
        setSearchError(null);
        setLastQuery(query);

        try {
            const startTime = Date.now();
            const response = await axios.post(`${API_BASE}/hunting/search`, query);
            const elapsed = Date.now() - startTime;
            setResults(response.data.results || []);
            setQueryStats({
                count: (response.data.results || []).length,
                ms: elapsed,
                conditions: query.conditions?.length || 0,
                logic: query.logic || 'AND'
            });
        } catch (err) {
            setResults([]);
            let message = 'Unable to execute hunt query.';
            const status = err.response?.status;
            if (status === 401) {
                message = 'Authentication required. Please log in again.';
            } else if (status === 403) {
                const detail = err.response?.data?.detail;
                const detailStr = typeof detail === 'string' ? detail : '';
                if (detailStr.toLowerCase().includes('csrf') || detailStr.toLowerCase().includes('custom request header') || detailStr.includes('Origin not allowed')) {
                    message = 'Security validation failed. Please refresh the session and try again.';
                } else if (detailStr.includes('Requires role') || detailStr.toLowerCase().includes('permission')) {
                    message = 'You do not have permission to perform this hunt.';
                } else {
                    message = detailStr || 'You do not have permission to perform this hunt.';
                }
            } else if (status === 422) {
                const detail = err.response?.data?.detail;
                if (typeof detail === 'string') {
                    message = detail;
                } else if (Array.isArray(detail)) {
                    message = detail.map(d => d.msg ? d.msg.replace(/^Value error,\s*/i, '') : JSON.stringify(d)).join('; ');
                } else {
                    message = 'Invalid hunt query parameters.';
                }
            } else if (status === 500) {
                message = 'Hunting service unavailable or internal backend error.';
            } else if (err.code === 'ECONNABORTED' || !err.response) {
                message = 'Network error: unable to reach the hunting service.';
            }
            setSearchError({ message, status });
        } finally {
            setLoading(false);
        }
    };

    const fetchCases = useCallback(async () => {
        try {
            const response = await axios.get(`${API_BASE}/cases/`);
            setCases(response.data);
        } catch {
            // Ignore fetch error
        }
    }, []);

    // Initial mount: load cases and latest hunt events automatically
    useEffect(() => {
        fetchCases();
        handleSearch({
            logic: 'AND',
            conditions: [{ field: 'threat_level', operator: 'equals', value: 'LOW' }],
            limit: 50
        });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [fetchCases]);

    // Live Event Ingestion from WebSocket
    useEffect(() => {
        if (!liveEvents || liveEvents.length === 0) return;
        const latest = liveEvents[0];
        if (!latest) return;

        const liveId = latest.id || latest.event_id || `live-${latest.src_ip}-${latest.timestamp || Date.now()}`;

        const formatted = {
            id: liveId,
            timestamp: latest.timestamp || new Date().toISOString(),
            src_ip: latest.src_ip || '127.0.0.1',
            dst_ip: latest.dst_ip || '127.0.0.1',
            src_port: latest.src_port || 0,
            dst_port: latest.dst_port || 0,
            protocol: latest.protocol || 'TCP',
            length: latest.length || 0,
            threat_score: typeof latest.threat_score === 'number'
                ? (latest.threat_score <= 1.0 ? latest.threat_score : latest.threat_score / 100)
                : 0.10,
            threat_level: latest.threat_level || (latest.threat_score >= 80 ? 'CRITICAL' : latest.threat_score >= 60 ? 'HIGH' : latest.threat_score >= 30 ? 'MEDIUM' : 'LOW'),
            attack_type: latest.attack_type || 'HONEYPOT_PROBE',
            is_malicious: latest.is_malicious ?? (latest.threat_score >= 60),
            payload_content: latest.raw_payload || latest.raw_data || '',
            confidence: latest.confidence || 0.95,
            is_live: true
        };

        if (liveMode) {
            if (autoStream) {
                setResults(prev => {
                    if (prev.some(e => e.id === formatted.id)) return prev;
                    return [formatted, ...prev].slice(0, 100);
                });
            } else {
                setLiveBuffer(prev => {
                    if (prev.some(e => e.id === formatted.id)) return prev;
                    return [formatted, ...prev].slice(0, 50);
                });
                setUnreadLiveCount(prev => prev + 1);
            }
        }
    }, [liveEvents, liveMode, autoStream]);

    const handleInjectLiveBuffer = () => {
        setResults(prev => [...liveBuffer, ...prev].slice(0, 100));
        setLiveBuffer([]);
        setUnreadLiveCount(0);
    };

    const handleEventSelect = async (event) => {
        setSelectedEvent(event);
        if (event && activeTab === 'correlation') {
            fetchCorrelation(event.src_ip);
        }
    };

    const fetchCorrelation = async (ip) => {
        if (!ip) return;
        setLoadingCorrelation(true);
        try {
            const response = await axios.get(`${API_BASE}/hunting/related-events?ip=${ip}`);
            setCorrelationData(response.data || []);
        } catch {
            // Ignore correlation error
        } finally {
            setLoadingCorrelation(false);
        }
    };

    const handlePivotSearch = (field, value) => {
        if (!field || !value) return;
        const query = {
            logic: 'AND',
            conditions: [{ field, operator: 'equals', value: String(value) }],
            limit: 100,
            offset: 0
        };
        handleSearch(query);
    };

    const handleTabChange = (tab) => {
        setActiveTab(tab);
        if (tab === 'correlation' && selectedEvent) {
            fetchCorrelation(selectedEvent.src_ip);
        }
    };

    const handleExport = async (format) => {
        setExportStatus('Generating...');
        const timestamp = new Date().toISOString().split('T')[0];
        const filename = `hunting_export_${timestamp}`;

        const exportData = results.map(r => ({
            Time: r.timestamp,
            Source: r.src_ip,
            Destination: `${r.dst_ip}:${r.dst_port}`,
            Protocol: r.protocol,
            'Threat Level': r.threat_level,
            'Attack Type': r.attack_type,
            'Threat Score': formatThreatScore(r.threat_score),
            'Is Malicious': r.is_malicious ? 'Yes' : 'No'
        }));

        if (format === 'csv') {
            exportToCSV(exportData, filename);
            setExportStatus('CSV Exported!');
        }
        if (format === 'json') {
            exportToJSON(exportData, filename);
            setExportStatus('JSON Exported!');
        }
        if (format === 'pdf') {
            const highCount = results.filter(r => r.threat_level === 'HIGH' || r.threat_level === 'CRITICAL').length;
            const protocols = [...new Set(results.map(r => r.protocol))].join(', ');
            generatePDF({
                title: 'Threat Hunting Investigation Report',
                description: 'Advanced multi-vector security event analysis from PhantomNet intelligence nodes.',
                timestamp: new Date().toLocaleString(),
                sections: [
                    {
                        title: 'Executive Summary',
                        content: `This report documents ${results.length} security events identified during active threat hunting operations. ` +
                            `${highCount} events were classified as HIGH or CRITICAL severity. ` +
                            `Protocols involved: ${protocols || 'N/A'}.`
                    },
                    {
                        title: 'Technical Events',
                        type: 'table',
                        headers: ['Time', 'Source IP', 'Protocol', 'Attack Type', 'Threat Score', 'Level'],
                        rows: results.map(r => [
                            r.timestamp ? new Date(r.timestamp).toLocaleString() : 'N/A',
                            r.src_ip,
                            r.protocol,
                            r.attack_type || 'Unknown',
                            formatThreatScore(r.threat_score),
                            r.threat_level || 'N/A'
                        ])
                    },
                    {
                        title: 'Investigation Notes',
                        content: selectedEvent
                            ? `Currently investigating event #${selectedEvent.id} from source IP ${selectedEvent.src_ip}. ` +
                            `Attack classification: ${selectedEvent.attack_type || 'Unknown'}. ` +
                            `Threat score: ${formatThreatScore(selectedEvent.threat_score)}.`
                            : 'No event selected for detailed investigation at time of export.'
                    }
                ]
            });
            setExportStatus('PDF Exported!');
        }
        setTimeout(() => setExportStatus(''), 3000);
    };

    const criticalCount = results.filter(r => r.threat_level === 'CRITICAL').length;
    const highCount = results.filter(r => r.threat_level === 'HIGH').length;
    const maliciousCount = results.filter(r => r.is_malicious).length;
    const uniqueIPs = new Set(results.map(r => r.src_ip)).size;

    return (
        <div className="threat-hunting-page">
            {/* ─── Header ─── */}
            <header className="hunting-header">
                <div className="header-left">
                    <div className="header-icon-wrap">
                        <Crosshair className="header-icon" />
                    </div>
                    <div>
                        <h1>Professional Threat Hunting</h1>
                        <p>Advanced multi-vector search · Case-based investigation · Targeted IOC extraction</p>
                    </div>
                </div>
                <div className="header-right">
                    {queryStats && (
                        <div className="query-stats-bar">
                            <span className="qs-item"><span className="qs-num">{queryStats.count}</span> events</span>
                            <span className="qs-sep">·</span>
                            <span className="qs-item"><span className="qs-num">{queryStats.ms}</span>ms</span>
                            <span className="qs-sep">·</span>
                            <span className="qs-item"><span className="qs-num">{queryStats.conditions}</span> filters · {queryStats.logic}</span>
                        </div>
                    )}
                    <button
                        type="button"
                        className={`status-badge session ${liveMode && isConnected ? 'live-active' : liveMode && !isConnected ? 'live-connecting' : 'live-paused'}`}
                        onClick={() => setLiveMode(prev => !prev)}
                        title={liveMode ? "Click to Pause Live Stream" : "Click to Resume Live Stream"}
                        style={{ cursor: 'pointer' }}
                    >
                        <Activity className={`w-3.5 h-3.5 ${liveMode && isConnected ? 'text-emerald-400 animate-pulse' : 'text-slate-400'}`} />
                        <span>
                            {liveMode ? (isConnected ? 'HUNTING SESSION · LIVE ACTIVE' : 'HUNTING SESSION · CONNECTING...') : 'HUNTING SESSION · PAUSED'}
                        </span>
                    </button>
                </div>
            </header>

            {/* ─── Stats Strip (visible after search) ─── */}
            {results.length > 0 && (
                <div className="hunt-stats-strip">
                    <div className="hss-item critical">
                        <TriangleAlert className="w-3.5 h-3.5" />
                        <span>{criticalCount} CRITICAL</span>
                    </div>
                    <div className="hss-item high">
                        <Shield className="w-3.5 h-3.5" />
                        <span>{highCount} HIGH</span>
                    </div>
                    <div className="hss-item malicious">
                        <Target className="w-3.5 h-3.5" />
                        <span>{maliciousCount} Malicious</span>
                    </div>
                    <div className="hss-item ips">
                        <Layers className="w-3.5 h-3.5" />
                        <span>{uniqueIPs} Unique IPs</span>
                    </div>
                </div>
            )}

            {/* ─── 3-Column Grid ─── */}
            <div className="hunting-grid">

                {/* ── Left Sidebar: Query Builder ── */}
                <aside className="hunting-sidebar query-section">
                    <div className="section-header">
                        <span className="sh-inner">
                            <Search className="w-3.5 h-3.5" />
                            Query Builder
                        </span>
                    </div>
                    <QueryBuilder onSearch={handleSearch} loading={loading} />
                </aside>

                {/* ── Main Content: Results ── */}
                <main className="hunting-main">
                    <div className="section-header main-header">
                        <div className="main-tabs">
                            <button
                                className={`tab-btn ${activeTab === 'timeline' ? 'active' : ''}`}
                                onClick={() => handleTabChange('timeline')}
                            >
                                <Database className="w-3 h-3" />
                                Timeline ({results.length})
                            </button>
                            <button
                                className={`tab-btn ${activeTab === 'correlation' ? 'active' : ''}`}
                                onClick={() => handleTabChange('correlation')}
                            >
                                <Layers className="w-3 h-3" />
                                IP Correlation {selectedEvent ? `(${correlationData.length})` : ''}
                            </button>
                            <button
                                type="button"
                                className={`tab-btn live-stream-toggle ${autoStream ? 'active' : ''}`}
                                onClick={() => setAutoStream(prev => !prev)}
                                title={autoStream ? "Auto-streaming active: incoming honeypot events prepend automatically" : "Auto-streaming paused: click to enable"}
                            >
                                <Zap className={`w-3 h-3 ${autoStream ? 'text-emerald-400' : 'text-slate-400'}`} />
                                {autoStream ? 'Auto-Stream ON' : 'Auto-Stream OFF'}
                            </button>
                        </div>

                        {results.length > 0 && (
                            <div className="export-actions">
                                <span className="export-status">{exportStatus}</span>
                                <button className="btn-export" onClick={() => handleExport('csv')} title="Export CSV">
                                    CSV
                                </button>
                                <button className="btn-export" onClick={() => handleExport('json')} title="Export JSON">
                                    JSON
                                </button>
                                <button className="btn-export pdf" onClick={() => handleExport('pdf')} title="Export PDF Report">
                                    <Download className="w-3 h-3" /> PDF Report
                                </button>
                            </div>
                        )}
                    </div>

                    <div className="main-content-area">
                        {unreadLiveCount > 0 && (
                            <div className="live-notification-bar" onClick={handleInjectLiveBuffer}>
                                <div className="lnb-left">
                                    <Zap className="w-4 h-4 text-emerald-400 animate-pulse" />
                                    <span><strong>{unreadLiveCount}</strong> new live honeypot probe{unreadLiveCount > 1 ? 's' : ''} captured — click to inject into timeline</span>
                                </div>
                                <button className="btn-inject-live">
                                    Load Live Events
                                </button>
                            </div>
                        )}

                        {loading ? (
                            <div className="loading-state">
                                <RefreshCw className="spin w-6 h-6 text-cyan-400" />
                                <span>Executing query across all honeypot nodes...</span>
                            </div>
                        ) : searchError ? (
                            <div className="search-error-banner">
                                <div className="search-error-content">
                                    <TriangleAlert className="w-5 h-5 text-red-500" />
                                    <div>
                                        <div style={{ fontWeight: 600, color: '#f87171' }}>
                                            Search Failed {searchError.status ? `(HTTP ${searchError.status})` : ''}
                                        </div>
                                        <div style={{ fontSize: '0.8rem', color: '#fca5a5', marginTop: '0.25rem' }}>
                                            {searchError.message}
                                        </div>
                                    </div>
                                </div>
                                {lastQuery && (
                                    <button className="search-error-retry" onClick={() => handleSearch(lastQuery)}>
                                        Retry Hunt
                                    </button>
                                )}
                            </div>
                        ) : activeTab === 'timeline' ? (
                            <EventTimeline
                                events={results}
                                onSelectEvent={handleEventSelect}
                                selectedEventId={selectedEvent?.id}
                            />
                        ) : (
                            <IPCorrelationPanel
                                selectedEvent={selectedEvent}
                                correlationData={correlationData}
                                loading={loadingCorrelation}
                            />
                        )}
                    </div>
                </main>

                {/* ── Right Sidebar: Investigation & Cases ── */}
                <aside className="hunting-sidebar case-section">
                    <div className="section-header">
                        <span className="sh-inner">
                            <Briefcase className="w-3.5 h-3.5" />
                            Investigation & Cases
                        </span>
                    </div>
                    <CaseManagement
                        selectedEvent={selectedEvent}
                        cases={cases}
                        onCaseUpdate={fetchCases}
                        onSelectEvent={handleEventSelect}
                        onPivotSearch={handlePivotSearch}
                    />
                </aside>
            </div>
        </div>
    );
};

/* ── Inline IP Correlation Panel ── */
const IPCorrelationPanel = ({ selectedEvent, correlationData, loading }) => {
    if (!selectedEvent) {
        return (
            <div className="timeline-empty">
                <Layers className="w-10 h-10 opacity-10 mb-3" />
                <p>Select an event from the Timeline tab to view IP correlation data.</p>
            </div>
        );
    }

    const getLevelColor = (level) => {
        switch (level) {
            case 'CRITICAL': return '#ef4444';
            case 'HIGH': return '#f97316';
            case 'MEDIUM': return '#eab308';
            case 'LOW': return '#22c55e';
            default: return '#64748b';
        }
    };

    return (
        <div className="correlation-panel">
            <div className="corr-focus-ip">
                <div className="cfi-label">Correlating events for source IP</div>
                <div className="cfi-ip">{selectedEvent.src_ip}</div>
                <div className="cfi-meta">
                    <span>Protocol: {selectedEvent.protocol}</span>
                    <span>Attack: {selectedEvent.attack_type || 'Unknown'}</span>
                    <span>Score: {formatThreatScore(selectedEvent.threat_score)}</span>
                </div>
            </div>

            {loading ? (
                <div className="loading-state small">
                    <RefreshCw className="spin w-5 h-5 text-cyan-400" />
                    <span>Correlating...</span>
                </div>
            ) : correlationData.length === 0 ? (
                <div className="corr-empty">No correlated events found for this IP in the current window.</div>
            ) : (
                <div className="corr-list">
                    <div className="corr-list-header">
                        <span>{correlationData.length} related events found</span>
                    </div>
                    {correlationData.map((ev, i) => (
                        <div key={ev.id || i} className="corr-item">
                            <div
                                className="corr-marker"
                                style={{ backgroundColor: getLevelColor(ev.threat_level) }}
                            />
                            <div className="corr-info">
                                <span className="corr-time">{new Date(ev.timestamp).toLocaleString()}</span>
                                <span className="corr-attack">{ev.attack_type || 'Observed Activity'}</span>
                            </div>
                            <div className="corr-score" style={{ color: getLevelColor(ev.threat_level) }}>
                                {formatThreatScore(ev.threat_score)}
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default ThreatHunting;

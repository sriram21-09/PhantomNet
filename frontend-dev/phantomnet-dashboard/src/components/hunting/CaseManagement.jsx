import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
    Plus, Briefcase, Link, Eye, EyeOff, Activity,
    Terminal, ShieldAlert, CheckCircle, X, MessageSquare,
    Share2, Clipboard
} from 'lucide-react';
import './CaseManagement.css';

const API_BASE = 'http://localhost:8000/api/v1';

const PRIORITY_COLORS = {
    Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22c55e'
};

const STATUS_COLORS = {
    Open: '#00d2ff', 'In Progress': '#a855f7', Closed: '#475569'
};

const CaseManagement = ({ selectedEvent, cases, onCaseUpdate }) => {
    const [iocs, setIocs] = useState([]);
    const [relatedEvents, setRelatedEvents] = useState([]);
    const [patterns, setPatterns] = useState([]);
    const [extracting, setExtracting] = useState(false);
    const [showNewCase, setShowNewCase] = useState(false);
    const [activeSection, setActiveSection] = useState('iocs'); // 'iocs' | 'related' | 'payload'
    const [newCaseData, setNewCaseData] = useState({
        title: '', description: '', priority: 'High', assigned_to: ''
    });
    const [inlineNote, setInlineNote] = useState('');
    const [copyFeedback, setCopyFeedback] = useState('');
    const [creating, setCreating] = useState(false);

    useEffect(() => {
        if (selectedEvent) {
            setIocs([]);
            setRelatedEvents([]);
            setPatterns([]);
            handleExtractIOCs();
            fetchRelatedAndPatterns();
            // Pre-fill case title from event
            setNewCaseData(prev => ({
                ...prev,
                title: `TH-${selectedEvent.id}: ${selectedEvent.attack_type || 'Investigation'} from ${selectedEvent.src_ip}`,
                description: `Investigating ${selectedEvent.attack_type || 'unknown attack'} from ${selectedEvent.src_ip} on ${selectedEvent.protocol} (score: ${Math.round(selectedEvent.threat_score)}).`
            }));
        } else {
            setIocs([]);
            setRelatedEvents([]);
            setPatterns([]);
        }
    }, [selectedEvent]);

    const handleExtractIOCs = async () => {
        setExtracting(true);
        try {
            const textToParse = [
                selectedEvent.src_ip,
                selectedEvent.dst_ip,
                selectedEvent.attack_type,
                selectedEvent.protocol,
                selectedEvent.raw_data || ''
            ].filter(Boolean).join(' ');
            const response = await axios.post(`${API_BASE}/hunting/extract-iocs`, { text: textToParse });
            setIocs(response.data || []);
        } catch {
            // graceful
        } finally {
            setExtracting(false);
        }
    };

    const fetchRelatedAndPatterns = async () => {
        try {
            const [relRes, patRes] = await Promise.all([
                axios.get(`${API_BASE}/hunting/related-events?ip=${selectedEvent.src_ip}`),
                axios.post(`${API_BASE}/hunting/analyze-patterns`, { text: selectedEvent.attack_type || '' })
            ]);
            setRelatedEvents(relRes.data || []);
            setPatterns(patRes.data || []);
        } catch { /* graceful */ }
    };

    const toggleWatchlist = (index) => {
        setIocs(prev => prev.map((ioc, i) =>
            i === index ? { ...ioc, inWatchlist: !ioc.inWatchlist } : ioc
        ));
    };

    const copyIOCsToClipboard = () => {
        const text = iocs.map(i => `${i.type}: ${i.value}`).join('\n');
        navigator.clipboard.writeText(text).then(() => {
            setCopyFeedback('Copied!');
            setTimeout(() => setCopyFeedback(''), 2000);
        });
    };

    const handleCreateCase = async (e) => {
        e.preventDefault();
        setCreating(true);
        try {
            const response = await axios.post(`${API_BASE}/cases/`, newCaseData);
            if (selectedEvent) {
                await axios.post(`${API_BASE}/cases/${response.data.id}/evidence`, {
                    event_id: selectedEvent.id,
                    event_type: 'packet_log',
                    notes: inlineNote || 'Initial evidence from threat hunting session.'
                });
            }
            setShowNewCase(false);
            setInlineNote('');
            setNewCaseData({ title: '', description: '', priority: 'High', assigned_to: '' });
            onCaseUpdate();
        } catch (err) {
            console.error('Failed to create case:', err);
        } finally {
            setCreating(false);
        }
    };

    const handleStatusUpdate = async (caseId, newStatus) => {
        try {
            await axios.put(`${API_BASE}/cases/${caseId}`, { status: newStatus });
            onCaseUpdate();
        } catch { /* graceful */ }
    };

    const handleAddToExistingCase = async (caseId) => {
        if (!selectedEvent) return;
        const note = inlineNote || 'Related event identified during threat hunting.';
        try {
            await axios.post(`${API_BASE}/cases/${caseId}/evidence`, {
                event_id: selectedEvent.id,
                event_type: 'packet_log',
                notes: note
            });
            onCaseUpdate();
        } catch { /* graceful */ }
    };

    const payload = selectedEvent?.raw_data ||
        `${selectedEvent?.attack_type || 'ACTIVITY'}\nsrc=${selectedEvent?.src_ip}:${selectedEvent?.src_port || '?'}\ndst=${selectedEvent?.dst_ip}:${selectedEvent?.dst_port}\nproto=${selectedEvent?.protocol}\nscore=${Math.round(selectedEvent?.threat_score || 0)}`;

    if (!selectedEvent && cases.length === 0) {
        return (
            <div className="cm-empty">
                <Briefcase className="cm-empty-icon" />
                <p>Select an event from the timeline to begin an investigation.</p>
            </div>
        );
    }

    return (
        <div className="case-management">

            {/* ── INVESTIGATION FOCUS ── */}
            {selectedEvent && (
                <div className="inv-focus">
                    <div className="inv-header">
                        <Activity className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Active Investigation</span>
                        <span className="inv-event-id">#{selectedEvent.id}</span>
                    </div>

                    {/* Quick Summary */}
                    <div className="inv-summary">
                        <div className="inv-field">
                            <label>Source IP</label>
                            <code className="inv-ip">{selectedEvent.src_ip}</code>
                        </div>
                        <div className="inv-field">
                            <label>Attack</label>
                            <span>{selectedEvent.attack_type || 'Unknown'}</span>
                        </div>
                        <div className="inv-field">
                            <label>Score</label>
                            <span className="inv-score">{Math.round(selectedEvent.threat_score)}</span>
                        </div>
                        <div className="inv-field">
                            <label>Protocol</label>
                            <span>{selectedEvent.protocol}</span>
                        </div>
                    </div>

                    {/* Section Tabs */}
                    <div className="inv-tabs">
                        {['iocs', 'related', 'payload'].map(tab => (
                            <button
                                key={tab}
                                className={`inv-tab ${activeSection === tab ? 'active' : ''}`}
                                onClick={() => setActiveSection(tab)}
                            >
                                {tab === 'iocs' ? `IOCs (${iocs.length})` :
                                    tab === 'related' ? `Related (${relatedEvents.length})` :
                                        'Payload'}
                            </button>
                        ))}
                    </div>

                    {/* IOCs Section */}
                    {activeSection === 'iocs' && (
                        <div className="inv-section-body">
                            {extracting ? (
                                <div className="cm-loading">Extracting IOCs...</div>
                            ) : iocs.length === 0 ? (
                                <div className="cm-none">No unique IOCs identified.</div>
                            ) : (
                                <>
                                    <div className="ioc-header-row">
                                        <span className="ioc-count">{iocs.length} artifacts</span>
                                        <button className="btn-copy" onClick={copyIOCsToClipboard}>
                                            <Clipboard className="w-3 h-3" />
                                            {copyFeedback || 'Copy All'}
                                        </button>
                                    </div>
                                    <div className="ioc-list">
                                        {iocs.map((ioc, idx) => (
                                            <div key={idx} className={`ioc-chip ${ioc.inWatchlist ? 'in-watchlist' : ''}`}>
                                                <span className="ioc-type">{ioc.type}</span>
                                                <span className="ioc-value">{ioc.value}</span>
                                                <button
                                                    className={`btn-watchlist ${ioc.inWatchlist ? 'active' : ''}`}
                                                    onClick={() => toggleWatchlist(idx)}
                                                    title={ioc.inWatchlist ? 'Remove from Watchlist' : 'Add to Watchlist'}
                                                >
                                                    {ioc.inWatchlist ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
                                                </button>
                                            </div>
                                        ))}
                                    </div>
                                </>
                            )}
                        </div>
                    )}

                    {/* Related Events Section */}
                    {activeSection === 'related' && (
                        <div className="inv-section-body">
                            {relatedEvents.length === 0 ? (
                                <div className="cm-none">No related events found in the current window.</div>
                            ) : (
                                <div className="related-list">
                                    {relatedEvents.slice(0, 6).map(re => (
                                        <div key={re.id} className="related-item">
                                            <div className="related-left">
                                                <span className="rel-id">#{re.id}</span>
                                                <span className="rel-proto">{re.protocol}</span>
                                            </div>
                                            <span className="rel-attack">{re.attack_type || 'Activity'}</span>
                                            <span className="rel-time">
                                                {re.timestamp ? new Date(re.timestamp).toLocaleTimeString() : ''}
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {patterns.length > 0 && (
                                <div className="patterns-section">
                                    <div className="patterns-label">Detected Patterns</div>
                                    <div className="patterns-list">
                                        {patterns.map(p => (
                                            <span key={p} className="pattern-tag">{p}</span>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Payload Section */}
                    {activeSection === 'payload' && (
                        <div className="inv-section-body">
                            <div className="payload-block">
                                <div className="payload-topbar">
                                    <Terminal className="w-3 h-3" />
                                    <span>Raw Payload Stream</span>
                                </div>
                                <pre className="payload-pre">{payload}</pre>
                            </div>
                            {patterns.length > 0 && (
                                <div className="patterns-list" style={{ marginTop: '0.5rem' }}>
                                    {patterns.map(p => (
                                        <span key={p} className="pattern-tag">{p} detected</span>
                                    ))}
                                </div>
                            )}
                        </div>
                    )}

                    {/* Inline Note + Case Actions */}
                    <div className="inv-note-block">
                        <div className="note-label">
                            <MessageSquare className="w-3 h-3" /> Investigation Note
                        </div>
                        <textarea
                            className="note-textarea"
                            placeholder="Add notes for this investigation..."
                            value={inlineNote}
                            onChange={e => setInlineNote(e.target.value)}
                            rows={2}
                        />
                    </div>

                    <div className="inv-case-actions">
                        <button className="btn-new-case" onClick={() => setShowNewCase(true)}>
                            <Plus className="w-3.5 h-3.5" /> New Case
                        </button>
                    </div>
                </div>
            )}

            {/* ── EXISTING CASES ── */}
            <div className="cases-section">
                <div className="cases-header">
                    <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />
                    <span>Open Cases ({cases.length})</span>
                </div>

                {cases.length === 0 ? (
                    <div className="cm-none" style={{ padding: '1rem' }}>No cases created yet.</div>
                ) : (
                    <div className="case-list">
                        {cases.map(c => (
                            <div key={c.id} className="case-card">
                                <div className="case-card-top">
                                    <span
                                        className="case-priority-tag"
                                        style={{ color: PRIORITY_COLORS[c.priority] || '#64748b', borderColor: `${PRIORITY_COLORS[c.priority] || '#64748b'}40` }}
                                    >
                                        {c.priority}
                                    </span>
                                    <select
                                        className="case-status-select"
                                        value={c.status}
                                        style={{ color: STATUS_COLORS[c.status] || '#64748b' }}
                                        onChange={e => handleStatusUpdate(c.id, e.target.value)}
                                    >
                                        <option>Open</option>
                                        <option>In Progress</option>
                                        <option>Closed</option>
                                    </select>
                                </div>
                                <h4 className="case-title">{c.title}</h4>
                                {c.description && (
                                    <p className="case-brief">{c.description.substring(0, 70)}{c.description.length > 70 ? '…' : ''}</p>
                                )}
                                {c.assigned_to && (
                                    <div className="case-assignee">→ {c.assigned_to}</div>
                                )}
                                <div className="case-card-actions">
                                    <button className="btn-icon-sm" title="View Case">
                                        <Eye className="w-3 h-3" />
                                    </button>
                                    {selectedEvent && (
                                        <button
                                            className="btn-link-event"
                                            onClick={() => handleAddToExistingCase(c.id)}
                                            title="Link selected event"
                                        >
                                            <Link className="w-3 h-3" /> Link Event
                                        </button>
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* ── NEW CASE MODAL ── */}
            {showNewCase && (
                <div className="cm-modal-overlay">
                    <div className="cm-modal">
                        <div className="cm-modal-header">
                            <h3>Initiate Investigation</h3>
                            <button className="btn-close" onClick={() => setShowNewCase(false)}>
                                <X className="w-4 h-4" />
                            </button>
                        </div>

                        <form onSubmit={handleCreateCase}>
                            <div className="cm-form-group">
                                <label>Case Title</label>
                                <input
                                    type="text"
                                    required
                                    value={newCaseData.title}
                                    placeholder="e.g. TH-42: SSH Brute Force from 192.168.x.x"
                                    onChange={e => setNewCaseData({ ...newCaseData, title: e.target.value })}
                                />
                            </div>
                            <div className="cm-form-group">
                                <label>Investigation Goals</label>
                                <textarea
                                    required
                                    rows={3}
                                    value={newCaseData.description}
                                    placeholder="Describe what you're investigating and initial findings..."
                                    onChange={e => setNewCaseData({ ...newCaseData, description: e.target.value })}
                                />
                            </div>
                            <div className="cm-form-row">
                                <div className="cm-form-group">
                                    <label>Priority</label>
                                    <select
                                        value={newCaseData.priority}
                                        onChange={e => setNewCaseData({ ...newCaseData, priority: e.target.value })}
                                    >
                                        <option>Low</option>
                                        <option>Medium</option>
                                        <option>High</option>
                                        <option>Critical</option>
                                    </select>
                                </div>
                                <div className="cm-form-group">
                                    <label>Assign To</label>
                                    <select
                                        value={newCaseData.assigned_to}
                                        onChange={e => setNewCaseData({ ...newCaseData, assigned_to: e.target.value })}
                                        required
                                    >
                                        <option value="" disabled>Select analyst...</option>
                                        <option>Analyst-01 (M. Reddy)</option>
                                        <option>Lead-Hunter (S. Kumar)</option>
                                        <option>SOC-Team-A</option>
                                        <option>Incident-Response-West</option>
                                    </select>
                                </div>
                            </div>
                            <div className="cm-form-group">
                                <label>Initial Notes</label>
                                <textarea
                                    rows={2}
                                    value={inlineNote}
                                    placeholder="Add initial analysis notes..."
                                    onChange={e => setInlineNote(e.target.value)}
                                />
                            </div>

                            <div className="cm-modal-actions">
                                <button type="button" className="btn-cancel" onClick={() => setShowNewCase(false)}>
                                    Cancel
                                </button>
                                <button type="submit" className="btn-confirm" disabled={creating}>
                                    <CheckCircle className="w-3.5 h-3.5" />
                                    {creating ? 'Creating...' : 'Create Case'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default CaseManagement;

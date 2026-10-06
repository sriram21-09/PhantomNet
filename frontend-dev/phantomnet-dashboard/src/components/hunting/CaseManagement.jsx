import React, { useState, useEffect, useCallback } from 'react';
import { createPortal } from 'react-dom';
import axios from 'axios';
import {
    Plus, Briefcase, Link, Eye, EyeOff, Activity,
    Terminal, ShieldAlert, CheckCircle, X, MessageSquare,
    Clipboard, Check, Crosshair, Search, Trash2, Download,
    User, AlertTriangle, ArrowRight, Layers, FileText
} from 'lucide-react';
import { generatePDF } from '../../utils/exportPDF';
import { exportToJSON } from '../../utils/exportUtils';
import './CaseManagement.css';

const API_BASE = '/api/v1';

const PRIORITY_COLORS = {
    Critical: '#ef4444',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#22c55e'
};

const STATUS_COLORS = {
    Open: '#00d2ff',
    'In Progress': '#a855f7',
    Closed: '#64748b'
};

const formatThreatScore = (score) => {
    if (score === null || score === undefined) return 0;
    const num = typeof score === 'number' ? score : parseFloat(score) || 0;
    return Math.round(num <= 1.0 ? num * 100 : num);
};

const fallbackCopy = (text, callback) => {
    try {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        if (callback) callback();
    } catch (err) {
        console.warn('Fallback copy error:', err);
    }
};

const copyText = (text, callback) => {
    if (navigator?.clipboard?.writeText) {
        navigator.clipboard.writeText(text)
            .then(callback)
            .catch(() => fallbackCopy(text, callback));
    } else {
        fallbackCopy(text, callback);
    }
};

const CaseManagement = ({
    selectedEvent,
    cases = [],
    onCaseUpdate,
    onSelectEvent,
    onPivotSearch
}) => {
    // Event Context States
    const [iocs, setIocs] = useState([]);
    const [relatedEvents, setRelatedEvents] = useState([]);
    const [patterns, setPatterns] = useState([]);
    const [extracting, setExtracting] = useState(false);
    const [activeSection, setActiveSection] = useState('iocs'); // 'iocs' | 'related' | 'payload'

    // Interactive Notes & Feedback
    const [inlineNote, setInlineNote] = useState('');
    const [savingNote, setSavingNote] = useState(false);
    const [noteFeedback, setNoteFeedback] = useState('');
    const [copyFeedback, setCopyFeedback] = useState('');
    const [copiedIocIdx, setCopiedIocIdx] = useState(null);
    const [copiedPayload, setCopiedPayload] = useState(false);
    const [linkFeedback, setLinkFeedback] = useState({}); // { [caseId]: 'linking' | 'linked' }

    // Case List Filter & Creation
    const [caseFilter, setCaseFilter] = useState('All'); // 'All' | 'Open' | 'In Progress' | 'Closed'
    const [showNewCase, setShowNewCase] = useState(false);
    const [newCaseData, setNewCaseData] = useState({
        title: '', description: '', priority: 'High', assigned_to: ''
    });
    const [assignees, setAssignees] = useState([]);
    const [creating, setCreating] = useState(false);
    const [selectedTargetCaseId, setSelectedTargetCaseId] = useState('');

    // Case Details Modal State
    const [selectedCaseForView, setSelectedCaseForView] = useState(null);
    const [caseEvidence, setCaseEvidence] = useState([]);
    const [loadingEvidence, setLoadingEvidence] = useState(false);
    const [modalNote, setModalNote] = useState('');
    const [addingModalNote, setAddingModalNote] = useState(false);
    const [modalFeedback, setModalFeedback] = useState('');

    const fetchAssignees = useCallback(async () => {
        try {
            const res = await axios.get(`${API_BASE}/cases/assignees`);
            setAssignees(res.data || []);
            if (res.data?.length > 0 && !newCaseData.assigned_to) {
                setNewCaseData(prev => ({ ...prev, assigned_to: res.data[0].username }));
            }
        } catch {
            setAssignees([]);
        }
    }, [newCaseData.assigned_to]);

    useEffect(() => {
        fetchAssignees();
    }, [fetchAssignees]);

    // Close modal on Escape key press
    useEffect(() => {
        const handleKeyDown = (e) => {
            if (e.key === 'Escape') {
                if (selectedCaseForView) setSelectedCaseForView(null);
                if (showNewCase) setShowNewCase(false);
            }
        };
        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [selectedCaseForView, showNewCase]);

    // Update target case for saving inline note
    useEffect(() => {
        if (cases.length > 0) {
            const activeCase = cases.find(c => c.status !== 'Closed') || cases[0];
            setSelectedTargetCaseId(String(activeCase.id));
        } else {
            setSelectedTargetCaseId('');
        }
    }, [cases]);

    // Handle Event Selection Change
    useEffect(() => {
        if (selectedEvent) {
            setIocs([]);
            setRelatedEvents([]);
            setPatterns([]);
            handleExtractIOCs();
            fetchRelatedAndPatterns();

            // Pre-fill case data
            const eventScore = formatThreatScore(selectedEvent.threat_score);
            const priority = eventScore >= 70 ? 'Critical' : eventScore >= 40 ? 'High' : eventScore >= 20 ? 'Medium' : 'Low';
            setNewCaseData(prev => ({
                ...prev,
                title: `TH-${selectedEvent.id}: ${selectedEvent.attack_type || 'Observed Threat'} from ${selectedEvent.src_ip}`,
                description: `Investigating ${selectedEvent.attack_type || 'activity'} from ${selectedEvent.src_ip}:${selectedEvent.src_port || '?'} targeting ${selectedEvent.dst_ip}:${selectedEvent.dst_port} (${selectedEvent.protocol}). Threat level: ${selectedEvent.threat_level || 'LOW'} (score: ${eventScore}).`,
                priority: priority
            }));
        } else {
            setIocs([]);
            setRelatedEvents([]);
            setPatterns([]);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [selectedEvent]);

    const handleExtractIOCs = async () => {
        if (!selectedEvent) return;
        setExtracting(true);
        try {
            const textToParse = [
                selectedEvent.src_ip,
                selectedEvent.dst_ip,
                selectedEvent.attack_type,
                selectedEvent.protocol,
                selectedEvent.payload_content || '',
                selectedEvent.raw_data || ''
            ].filter(Boolean).join(' ');
            const response = await axios.post(`${API_BASE}/hunting/extract-iocs`, { text: textToParse });
            setIocs(response.data || []);
        } catch {
            const fallback = [];
            if (selectedEvent.src_ip) fallback.push({ type: 'IP', value: selectedEvent.src_ip, in_watchlist: false });
            if (selectedEvent.dst_ip) fallback.push({ type: 'IP', value: selectedEvent.dst_ip, in_watchlist: false });
            setIocs(fallback);
        } finally {
            setExtracting(false);
        }
    };

    const fetchRelatedAndPatterns = async () => {
        if (!selectedEvent?.src_ip) return;
        try {
            const [relRes, patRes] = await Promise.all([
                axios.get(`${API_BASE}/hunting/related-events?ip=${selectedEvent.src_ip}`).catch(() => ({ data: [] })),
                axios.post(`${API_BASE}/hunting/analyze-patterns`, { text: selectedEvent.attack_type || selectedEvent.payload_content || '' }).catch(() => ({ data: [] }))
            ]);
            setRelatedEvents(relRes.data || []);
            setPatterns(patRes.data || []);
        } catch {
            // graceful
        }
    };

    const toggleWatchlist = async (index) => {
        const target = iocs[index];
        if (!target) return;
        try {
            const res = await axios.post(`${API_BASE}/hunting/watchlist/toggle`, {
                type: target.type,
                value: target.value
            });
            const newStatus = res.data.in_watchlist;
            setIocs(prev => prev.map((ioc, i) =>
                i === index ? { ...ioc, in_watchlist: newStatus, inWatchlist: newStatus } : ioc
            ));
        } catch (err) {
            console.error('Failed to toggle IOC watchlist:', err);
        }
    };

    const copyIOCsToClipboard = () => {
        const text = iocs.map(i => `${i.type}: ${i.value}`).join('\n');
        copyText(text, () => {
            setCopyFeedback('Copied!');
            setTimeout(() => setCopyFeedback(''), 2000);
        });
    };

    const copySingleIOC = (val, idx) => {
        copyText(val, () => {
            setCopiedIocIdx(idx);
            setTimeout(() => setCopiedIocIdx(null), 1800);
        });
    };

    const copyPayload = () => {
        copyText(payload, () => {
            setCopiedPayload(true);
            setTimeout(() => setCopiedPayload(false), 2000);
        });
    };

    // Save Note to Selected Case directly
    const handleSaveNoteToCase = async () => {
        if (!inlineNote.trim()) return;
        if (!selectedTargetCaseId) {
            setShowNewCase(true);
            return;
        }

        setSavingNote(true);
        try {
            await axios.post(`${API_BASE}/cases/${selectedTargetCaseId}/notes`, {
                notes: inlineNote.trim()
            });
            setNoteFeedback('Note saved! ✓');
            setInlineNote('');
            if (onCaseUpdate) onCaseUpdate();
            setTimeout(() => setNoteFeedback(''), 2500);
        } catch (err) {
            console.error('Failed to save note to case:', err);
            setNoteFeedback('Save failed');
            setTimeout(() => setNoteFeedback(''), 2500);
        } finally {
            setSavingNote(false);
        }
    };

    // Create New Case
    const handleCreateCase = async (e) => {
        e.preventDefault();
        setCreating(true);
        try {
            const response = await axios.post(`${API_BASE}/cases/`, newCaseData);
            const createdCase = response.data;

            if (selectedEvent) {
                await axios.post(`${API_BASE}/cases/${createdCase.id}/evidence`, {
                    event_id: selectedEvent.id,
                    event_type: 'packet_log',
                    notes: inlineNote.trim() || 'Initial trigger event identified during Threat Hunting.'
                });
            } else if (inlineNote.trim()) {
                await axios.post(`${API_BASE}/cases/${createdCase.id}/notes`, {
                    notes: inlineNote.trim()
                });
            }

            setShowNewCase(false);
            setInlineNote('');
            setNewCaseData({ title: '', description: '', priority: 'High', assigned_to: assignees[0]?.username || '' });
            if (onCaseUpdate) onCaseUpdate();
        } catch (err) {
            console.error('Case creation failed:', err);
        } finally {
            setCreating(false);
        }
    };

    // Update Status of a Case
    const handleStatusUpdate = async (caseId, newStatus) => {
        try {
            await axios.put(`${API_BASE}/cases/${caseId}`, { status: newStatus });
            if (selectedCaseForView && selectedCaseForView.id === caseId) {
                setSelectedCaseForView(prev => ({ ...prev, status: newStatus }));
            }
            if (onCaseUpdate) onCaseUpdate();
        } catch (err) {
            console.error('Failed to update case status:', err);
        }
    };

    // Update Priority of a Case
    const handlePriorityUpdate = async (caseId, newPriority) => {
        try {
            await axios.put(`${API_BASE}/cases/${caseId}`, { priority: newPriority });
            if (selectedCaseForView && selectedCaseForView.id === caseId) {
                setSelectedCaseForView(prev => ({ ...prev, priority: newPriority }));
            }
            if (onCaseUpdate) onCaseUpdate();
        } catch (err) {
            console.error('Failed to update case priority:', err);
        }
    };

    // Reassign Analyst
    const handleReassign = async (caseId, newAssignee) => {
        try {
            await axios.put(`${API_BASE}/cases/${caseId}`, { assigned_to: newAssignee });
            if (selectedCaseForView && selectedCaseForView.id === caseId) {
                setSelectedCaseForView(prev => ({ ...prev, assigned_to: newAssignee }));
            }
            if (onCaseUpdate) onCaseUpdate();
        } catch (err) {
            console.error('Failed to reassign case:', err);
        }
    };

    // Link Current Event to an Existing Case
    const handleAddToExistingCase = async (caseId) => {
        if (!selectedEvent) return;
        setLinkFeedback(prev => ({ ...prev, [caseId]: 'linking' }));
        const note = inlineNote.trim() || `Linked event #${selectedEvent.id} (${selectedEvent.protocol} ${selectedEvent.attack_type || 'anomaly'}).`;

        try {
            await axios.post(`${API_BASE}/cases/${caseId}/evidence`, {
                event_id: selectedEvent.id,
                event_type: 'packet_log',
                notes: note
            });
            setLinkFeedback(prev => ({ ...prev, [caseId]: 'linked' }));
            setInlineNote('');
            if (onCaseUpdate) onCaseUpdate();
            setTimeout(() => {
                setLinkFeedback(prev => ({ ...prev, [caseId]: null }));
            }, 3000);
        } catch (err) {
            console.error('Failed to link event to case:', err);
            setLinkFeedback(prev => ({ ...prev, [caseId]: 'error' }));
            setTimeout(() => {
                setLinkFeedback(prev => ({ ...prev, [caseId]: null }));
            }, 3000);
        }
    };

    // Open Case Details Modal & Fetch Evidence
    const handleOpenCaseDetails = async (caseItem) => {
        setSelectedCaseForView(caseItem);
        setLoadingEvidence(true);
        setModalNote('');
        setModalFeedback('');
        try {
            const res = await axios.get(`${API_BASE}/cases/${caseItem.id}/evidence`);
            setCaseEvidence(res.data || []);
        } catch (err) {
            console.error('Failed to load case evidence:', err);
            setCaseEvidence([]);
        } finally {
            setLoadingEvidence(false);
        }
    };

    // Add Note from inside Case Details Modal
    const handleAddModalNote = async () => {
        if (!modalNote.trim() || !selectedCaseForView) return;
        setAddingModalNote(true);
        try {
            await axios.post(`${API_BASE}/cases/${selectedCaseForView.id}/notes`, {
                notes: modalNote.trim()
            });
            setModalNote('');
            setModalFeedback('Note added! ✓');
            const res = await axios.get(`${API_BASE}/cases/${selectedCaseForView.id}/evidence`);
            setCaseEvidence(res.data || []);
            if (onCaseUpdate) onCaseUpdate();
            setTimeout(() => setModalFeedback(''), 2500);
        } catch (err) {
            console.error('Failed to add modal note:', err);
        } finally {
            setAddingModalNote(false);
        }
    };

    // Detach Evidence from Case
    const handleDetachEvidence = async (evidenceId) => {
        if (!selectedCaseForView) return;
        try {
            await axios.delete(`${API_BASE}/cases/${selectedCaseForView.id}/evidence/${evidenceId}`);
            setCaseEvidence(prev => prev.filter(ev => ev.id !== evidenceId));
            if (onCaseUpdate) onCaseUpdate();
        } catch (err) {
            console.error('Failed to detach evidence:', err);
        }
    };

    // Delete Entire Case
    const handleDeleteCase = async (caseId) => {
        if (!window.confirm(`Are you sure you want to permanently delete Case #${caseId}?`)) return;
        try {
            await axios.delete(`${API_BASE}/cases/${caseId}`);
            setSelectedCaseForView(null);
            if (onCaseUpdate) onCaseUpdate();
        } catch (err) {
            console.error('Failed to delete case:', err);
        }
    };

    // Export Official PDF Report File
    const handleExportCasePDF = (caseItem) => {
        try {
            const rows = caseEvidence.map(e => [
                e.event_id ? `#${e.event_id}` : `Evidence #${e.id}`,
                e.event_type || 'packet_log',
                e.event_details ? `${e.event_details.src_ip} -> ${e.event_details.dst_ip}:${e.event_details.dst_port}` : 'N/A',
                e.event_details?.protocol || 'TCP',
                e.event_details ? String(formatThreatScore(e.event_details.threat_score)) : '0',
                e.notes || '-'
            ]);

            generatePDF({
                title: `Case #${caseItem.id} Forensic Dossier`,
                description: `Official forensic incident dossier for Case #${caseItem.id} - ${caseItem.title}`,
                timestamp: new Date().toLocaleString(),
                sections: [
                    {
                        title: "Executive Summary & Incident Metadata",
                        content: `Case Title: ${caseItem.title}\nStatus: ${caseItem.status} | Priority: ${caseItem.priority} | Lead Analyst: ${caseItem.assigned_to || 'Unassigned'}\nCreated At: ${new Date(caseItem.created_at).toLocaleString()} | Last Updated: ${new Date(caseItem.updated_at).toLocaleString()}`
                    },
                    {
                        title: "Investigation Scope & Objectives",
                        content: caseItem.description || "No description provided."
                    },
                    {
                        title: `Attached Evidence & Telemetry (${caseEvidence.length} items)`,
                        type: "table",
                        headers: ["Event ID", "Type", "Source -> Destination", "Protocol", "Score", "Notes"],
                        rows: rows.length > 0 ? rows : [["-", "-", "No evidence items attached", "-", "-", "-"]]
                    }
                ]
            });

            setModalFeedback('PDF Report Downloaded! ✓');
            setTimeout(() => setModalFeedback(''), 3000);
        } catch (err) {
            console.error('Failed to generate PDF:', err);
            setModalFeedback('PDF generation error');
            setTimeout(() => setModalFeedback(''), 3000);
        }
    };

    // Download Case Data as JSON
    const handleExportCaseJSON = (caseItem) => {
        try {
            const exportObj = {
                id: caseItem.id,
                title: caseItem.title,
                status: caseItem.status,
                priority: caseItem.priority,
                assigned_to: caseItem.assigned_to,
                created_at: caseItem.created_at,
                updated_at: caseItem.updated_at,
                description: caseItem.description,
                evidence_count: caseEvidence.length,
                evidence: caseEvidence
            };
            exportToJSON(exportObj, `Case_${caseItem.id}_Forensic_Report`);
            setModalFeedback('JSON Report Downloaded! ✓');
            setTimeout(() => setModalFeedback(''), 3000);
        } catch (err) {
            console.error('Failed to export JSON:', err);
        }
    };

    // Copy Text Summary to Clipboard
    const handleCopyCaseText = (caseItem) => {
        const evList = caseEvidence.map(e => {
            if (e.event_details) {
                return `- Event #${e.event_id}: ${e.event_details.src_ip} -> ${e.event_details.dst_ip}:${e.event_details.dst_port} (${e.event_details.protocol}) [Score: ${formatThreatScore(e.event_details.threat_score)}] Notes: ${e.notes || 'None'}`;
            }
            return `- [${e.event_type.toUpperCase()}] ${e.notes || 'No description'}`;
        }).join('\n');

        const summary = `
========================================
PHANTOMNET CASE REPORT: #${caseItem.id}
========================================
Title: ${caseItem.title}
Status: ${caseItem.status}
Priority: ${caseItem.priority}
Assignee: ${caseItem.assigned_to || 'Unassigned'}
Created: ${new Date(caseItem.created_at).toLocaleString()}
Last Updated: ${new Date(caseItem.updated_at).toLocaleString()}

GOALS / DESCRIPTION:
${caseItem.description}

ATTACHED EVIDENCE & ARTIFACTS (${caseEvidence.length}):
${evList || 'No evidence items attached.'}
========================================
Generated by PhantomNet Threat Hunting Engine
`.trim();

        copyText(summary, () => {
            setModalFeedback('Text Summary Copied! ✓');
            setTimeout(() => setModalFeedback(''), 2500);
        });
    };

    const payload = selectedEvent?.payload_content || selectedEvent?.raw_data ||
        `${selectedEvent?.attack_type || 'ACTIVITY'}\nsrc=${selectedEvent?.src_ip}:${selectedEvent?.src_port || '?'}\ndst=${selectedEvent?.dst_ip}:${selectedEvent?.dst_port}\nproto=${selectedEvent?.protocol}\nscore=${formatThreatScore(selectedEvent?.threat_score || 0)}`;

    const filteredCases = cases.filter(c => {
        if (caseFilter === 'All') return true;
        return c.status === caseFilter;
    });

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

            {/* ── ACTIVE INVESTIGATION FOCUS ── */}
            {selectedEvent ? (
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
                            <code
                                className="inv-ip clickable-ip"
                                title="Click to filter search by this IP"
                                onClick={() => onPivotSearch?.('src_ip', selectedEvent.src_ip)}
                            >
                                {selectedEvent.src_ip}
                            </code>
                        </div>
                        <div className="inv-field">
                            <label>Attack Vector</label>
                            <span
                                className="clickable-attack"
                                title="Click to search for this attack type"
                                onClick={() => onPivotSearch?.('attack_type', selectedEvent.attack_type)}
                            >
                                {selectedEvent.attack_type || 'Unknown'}
                            </span>
                        </div>
                        <div className="inv-field">
                            <label>Threat Score</label>
                            <span className="inv-score">{formatThreatScore(selectedEvent.threat_score)}</span>
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
                                        <button className="btn-copy" onClick={copyIOCsToClipboard} title="Copy all artifacts">
                                            {copyFeedback ? <Check className="w-3 h-3 text-emerald-400" /> : <Clipboard className="w-3 h-3" />}
                                            {copyFeedback || 'Copy All'}
                                        </button>
                                    </div>
                                    <div className="ioc-list">
                                        {iocs.map((ioc, idx) => {
                                            const inWl = ioc.in_watchlist ?? ioc.inWatchlist;
                                            const isCopied = copiedIocIdx === idx;
                                            return (
                                                <div key={idx} className={`ioc-chip ${inWl ? 'in-watchlist' : ''}`}>
                                                    <span className="ioc-type">{ioc.type}</span>
                                                    <span
                                                        className="ioc-value"
                                                        title="Click to hunt/filter for this IOC"
                                                        onClick={() => onPivotSearch?.(ioc.type === 'IP' ? 'src_ip' : 'payload_content', ioc.value)}
                                                    >
                                                        {ioc.value}
                                                    </span>
                                                    <div className="ioc-actions">
                                                        <button
                                                            type="button"
                                                            className="btn-ioc-action"
                                                            onClick={() => onPivotSearch?.(ioc.type === 'IP' ? 'src_ip' : 'payload_content', ioc.value)}
                                                            title="Pivot Hunt on this IOC"
                                                        >
                                                            <Crosshair className="w-3 h-3 text-cyan-400" />
                                                        </button>
                                                        <button
                                                            type="button"
                                                            className="btn-ioc-action"
                                                            onClick={() => copySingleIOC(ioc.value, idx)}
                                                            title="Copy IOC value"
                                                        >
                                                            {isCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Clipboard className="w-3 h-3" />}
                                                        </button>
                                                        <button
                                                            type="button"
                                                            className={`btn-watchlist ${inWl ? 'active' : ''}`}
                                                            onClick={() => toggleWatchlist(idx)}
                                                            title={inWl ? 'Remove from Watchlist' : 'Add to Watchlist'}
                                                        >
                                                            {inWl ? <Eye className="w-3 h-3 text-purple-400" /> : <EyeOff className="w-3 h-3 text-slate-400" />}
                                                        </button>
                                                    </div>
                                                </div>
                                            );
                                        })}
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
                                <div className="related-list scrollable-related">
                                    {relatedEvents.map(re => (
                                        <div
                                            key={re.id}
                                            className="related-item clickable-related"
                                            onClick={() => onSelectEvent?.(re)}
                                            title="Click to inspect this event in timeline"
                                        >
                                            <div className="related-left">
                                                <span className="rel-id">#{re.id}</span>
                                                <span className="rel-proto">{re.protocol}</span>
                                            </div>
                                            <span className="rel-attack">{re.attack_type || 'Activity'}</span>
                                            <span className="rel-time">
                                                {re.timestamp ? new Date(re.timestamp).toLocaleTimeString() : ''}
                                            </span>
                                            <ArrowRight className="w-3 h-3 text-slate-500 rel-arrow" />
                                        </div>
                                    ))}
                                </div>
                            )}

                            {patterns.length > 0 && (
                                <div className="patterns-section">
                                    <div className="patterns-label">Detected Attack Signatures</div>
                                    <div className="patterns-list">
                                        {patterns.map(p => (
                                            <span
                                                key={p}
                                                className="pattern-tag clickable-tag"
                                                onClick={() => onPivotSearch?.('attack_type', p)}
                                                title="Click to search for this attack pattern"
                                            >
                                                <Search className="w-2.5 h-2.5 mr-1" />
                                                {p}
                                            </span>
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
                                    <div className="payload-top-left">
                                        <Terminal className="w-3 h-3" />
                                        <span>Raw Payload Stream</span>
                                    </div>
                                    <button className="btn-copy-payload" onClick={copyPayload} title="Copy full payload">
                                        {copiedPayload ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Clipboard className="w-2.5 h-2.5" />}
                                        {copiedPayload ? 'Copied' : 'Copy'}
                                    </button>
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

                    {/* Inline Investigation Note */}
                    <div className="inv-note-block">
                        <div className="note-label">
                            <MessageSquare className="w-3 h-3" /> Investigation Note
                            {noteFeedback && <span className="note-feedback-badge">{noteFeedback}</span>}
                        </div>
                        <textarea
                            className="note-textarea"
                            placeholder="Add notes for this investigation..."
                            value={inlineNote}
                            onChange={e => setInlineNote(e.target.value)}
                            rows={2}
                        />
                        <div className="note-action-bar">
                            {cases.length > 0 ? (
                                <div className="note-save-row">
                                    <select
                                        className="note-case-select"
                                        value={selectedTargetCaseId}
                                        onChange={e => setSelectedTargetCaseId(e.target.value)}
                                        title="Select target case for note"
                                    >
                                        {cases.map(c => (
                                            <option key={c.id} value={c.id}>
                                                Case #{c.id}: {c.title.slice(0, 24)}...
                                            </option>
                                        ))}
                                    </select>
                                    <button
                                        type="button"
                                        className="btn-save-note"
                                        disabled={!inlineNote.trim() || savingNote}
                                        onClick={handleSaveNoteToCase}
                                    >
                                        {savingNote ? 'Saving...' : 'Save Note to Case'}
                                    </button>
                                </div>
                            ) : (
                                <span className="note-hint">Notes will be attached when creating a new case</span>
                            )}
                        </div>
                    </div>

                    <div className="inv-case-actions">
                        <button className="btn-new-case" onClick={() => setShowNewCase(true)}>
                            <Plus className="w-3.5 h-3.5" /> New Case
                        </button>
                    </div>
                </div>
            ) : (
                <div className="inv-unselected-hint">
                    <p>Select any event in the timeline to focus the investigation panel.</p>
                    <button className="btn-new-case" onClick={() => setShowNewCase(true)}>
                        <Plus className="w-3.5 h-3.5" /> Create Case
                    </button>
                </div>
            )}

            {/* ── CASES LIST SECTION ── */}
            <div className="cases-section">
                <div className="cases-header">
                    <div className="cases-header-left">
                        <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />
                        <span>Cases ({filteredCases.length})</span>
                    </div>
                    <div className="cases-filter-pills">
                        {['All', 'Open', 'In Progress', 'Closed'].map(status => (
                            <button
                                key={status}
                                className={`case-filter-pill ${caseFilter === status ? 'active' : ''}`}
                                onClick={() => setCaseFilter(status)}
                            >
                                {status}
                            </button>
                        ))}
                    </div>
                </div>

                {filteredCases.length === 0 ? (
                    <div className="cm-none" style={{ padding: '1.25rem' }}>
                        No {caseFilter !== 'All' ? caseFilter.toLowerCase() : ''} cases found.
                    </div>
                ) : (
                    <div className="case-list">
                        {filteredCases.map(c => {
                            const linkState = linkFeedback[c.id];
                            return (
                                <div key={c.id} className="case-card">
                                    <div className="case-card-top">
                                        <span
                                            className="case-priority-tag"
                                            style={{
                                                color: PRIORITY_COLORS[c.priority] || '#64748b',
                                                borderColor: `${PRIORITY_COLORS[c.priority] || '#64748b'}40`,
                                                background: `${PRIORITY_COLORS[c.priority] || '#64748b'}10`
                                            }}
                                        >
                                            {c.priority}
                                        </span>
                                        <select
                                            className="case-status-select"
                                            value={c.status}
                                            style={{ color: STATUS_COLORS[c.status] || '#64748b' }}
                                            onChange={e => handleStatusUpdate(c.id, e.target.value)}
                                        >
                                            <option value="Open">Open</option>
                                            <option value="In Progress">In Progress</option>
                                            <option value="Closed">Closed</option>
                                        </select>
                                    </div>

                                    <h4
                                        className="case-title clickable-title"
                                        onClick={() => handleOpenCaseDetails(c)}
                                        title="Click to view full case details"
                                    >
                                        {c.title}
                                    </h4>

                                    {c.description && (
                                        <p className="case-brief">
                                            {c.description.substring(0, 85)}{c.description.length > 85 ? '…' : ''}
                                        </p>
                                    )}

                                    <div className="case-meta-row">
                                        {c.assigned_to && (
                                            <div className="case-assignee">
                                                <User className="w-2.5 h-2.5 inline mr-1 opacity-70" />
                                                → {c.assigned_to}
                                            </div>
                                        )}
                                        <span className="case-time">
                                            {new Date(c.created_at).toLocaleDateString()}
                                        </span>
                                    </div>

                                    <div className="case-card-actions">
                                        <button
                                            type="button"
                                            className="btn-icon-sm"
                                            onClick={() => handleOpenCaseDetails(c)}
                                            title="View Full Case Details & Evidence"
                                        >
                                            <Eye className="w-3 h-3" />
                                        </button>

                                        {selectedEvent && (
                                            <button
                                                type="button"
                                                className={`btn-link-event ${linkState === 'linked' ? 'linked' : ''}`}
                                                disabled={linkState === 'linking'}
                                                onClick={() => handleAddToExistingCase(c.id)}
                                                title="Link current event to this case"
                                            >
                                                {linkState === 'linking' ? (
                                                    <span>Linking...</span>
                                                ) : linkState === 'linked' ? (
                                                    <>
                                                        <Check className="w-3 h-3 text-emerald-400" /> Linked ✓
                                                    </>
                                                ) : (
                                                    <>
                                                        <Link className="w-3 h-3" /> Link Event
                                                    </>
                                                )}
                                            </button>
                                        )}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>

            {/* ── NEW CASE CREATION MODAL (PORTAL) ── */}
            {showNewCase && typeof document !== 'undefined' && createPortal(
                <div
                    className="cm-modal-overlay"
                    onClick={(e) => {
                        if (e.target === e.currentTarget) setShowNewCase(false);
                    }}
                >
                    <div className="cm-modal">
                        <div className="cm-modal-header">
                            <div className="cm-modal-header-left">
                                <Briefcase className="w-4 h-4 text-purple-400" />
                                <h3>Initiate Threat Investigation</h3>
                            </div>
                            <button
                                type="button"
                                className="btn-close"
                                onClick={() => setShowNewCase(false)}
                                title="Close modal"
                            >
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
                                <label>Investigation Goals & Scope</label>
                                <textarea
                                    required
                                    rows={3}
                                    value={newCaseData.description}
                                    placeholder="Describe observed attack behavior, affected services, and remediation goals..."
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
                                        <option value="Low">Low</option>
                                        <option value="Medium">Medium</option>
                                        <option value="High">High</option>
                                        <option value="Critical">Critical</option>
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
                                        {assignees.length === 0 ? (
                                            <option value="admin">admin (Admin)</option>
                                        ) : (
                                            assignees.map(a => (
                                                <option key={a.id} value={a.username}>{a.username} ({a.role})</option>
                                            ))
                                        )}
                                    </select>
                                </div>
                            </div>
                            <div className="cm-form-group">
                                <label>Initial Notes / Evidence Summary</label>
                                <textarea
                                    rows={2}
                                    value={inlineNote}
                                    placeholder="Add initial notes from current investigation..."
                                    onChange={e => setInlineNote(e.target.value)}
                                />
                            </div>

                            <div className="cm-modal-actions">
                                <button type="button" className="btn-cancel" onClick={() => setShowNewCase(false)}>
                                    Cancel
                                </button>
                                <button type="submit" className="btn-confirm" disabled={creating}>
                                    <CheckCircle className="w-3.5 h-3.5 mr-1" />
                                    {creating ? 'Creating...' : 'Create Case'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>,
                document.body
            )}

            {/* ── CASE DETAILS & EVIDENCE MODAL (PORTAL) ── */}
            {selectedCaseForView && typeof document !== 'undefined' && createPortal(
                <div
                    className="cm-modal-overlay"
                    onClick={(e) => {
                        if (e.target === e.currentTarget) setSelectedCaseForView(null);
                    }}
                >
                    <div className="cm-modal case-details-modal">
                        <div className="cm-modal-header">
                            <div className="cm-modal-header-left">
                                <span className="case-id-badge">#{selectedCaseForView.id}</span>
                                <h3>{selectedCaseForView.title}</h3>
                            </div>
                            <button
                                type="button"
                                className="btn-close"
                                onClick={() => setSelectedCaseForView(null)}
                                title="Close modal"
                            >
                                <X className="w-4 h-4" />
                            </button>
                        </div>

                        {modalFeedback && (
                            <div className="modal-feedback-banner">
                                <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                                <span>{modalFeedback}</span>
                            </div>
                        )}

                        <div className="case-details-body">
                            {/* Controls Row */}
                            <div className="cd-controls-grid">
                                <div className="cd-control-item">
                                    <label>Status</label>
                                    <select
                                        className="cd-select"
                                        value={selectedCaseForView.status}
                                        onChange={e => handleStatusUpdate(selectedCaseForView.id, e.target.value)}
                                    >
                                        <option value="Open">Open</option>
                                        <option value="In Progress">In Progress</option>
                                        <option value="Closed">Closed</option>
                                    </select>
                                </div>
                                <div className="cd-control-item">
                                    <label>Priority</label>
                                    <select
                                        className="cd-select"
                                        value={selectedCaseForView.priority}
                                        onChange={e => handlePriorityUpdate(selectedCaseForView.id, e.target.value)}
                                    >
                                        <option value="Low">Low</option>
                                        <option value="Medium">Medium</option>
                                        <option value="High">High</option>
                                        <option value="Critical">Critical</option>
                                    </select>
                                </div>
                                <div className="cd-control-item">
                                    <label>Assignee</label>
                                    <select
                                        className="cd-select"
                                        value={selectedCaseForView.assigned_to || ''}
                                        onChange={e => handleReassign(selectedCaseForView.id, e.target.value)}
                                    >
                                        {assignees.map(a => (
                                            <option key={a.id} value={a.username}>{a.username} ({a.role})</option>
                                        ))}
                                    </select>
                                </div>
                            </div>

                            {/* Description / Scope */}
                            <div className="cd-section">
                                <div className="cd-section-title">
                                    <FileText className="w-3.5 h-3.5 text-cyan-400" />
                                    <span>Scope & Objectives</span>
                                </div>
                                <p className="cd-description">{selectedCaseForView.description}</p>
                            </div>

                            {/* Evidence & Attached Packets */}
                            <div className="cd-section">
                                <div className="cd-section-title">
                                    <Layers className="w-3.5 h-3.5 text-purple-400" />
                                    <span>Attached Evidence & Telemetry ({caseEvidence.length})</span>
                                </div>

                                {loadingEvidence ? (
                                    <div className="cm-loading">Loading evidence artifacts...</div>
                                ) : caseEvidence.length === 0 ? (
                                    <div className="cm-none">No evidence attached to this case yet.</div>
                                ) : (
                                    <div className="evidence-list">
                                        {caseEvidence.map(ev => (
                                            <div key={ev.id} className="evidence-card">
                                                <div className="ev-header">
                                                    <div className="ev-type-wrap">
                                                        <span className="ev-badge">{ev.event_type}</span>
                                                        {ev.event_id && <span className="ev-id">#{ev.event_id}</span>}
                                                    </div>
                                                    <button
                                                        type="button"
                                                        className="btn-ev-delete"
                                                        onClick={() => handleDetachEvidence(ev.id)}
                                                        title="Detach Evidence"
                                                    >
                                                        <Trash2 className="w-3 h-3" />
                                                    </button>
                                                </div>

                                                {ev.event_details ? (
                                                    <div className="ev-details">
                                                        <div className="ev-ips">
                                                            <code>{ev.event_details.src_ip}</code>
                                                            <span>→</span>
                                                            <code>{ev.event_details.dst_ip}:{ev.event_details.dst_port}</code>
                                                            <span className="ev-proto">({ev.event_details.protocol})</span>
                                                        </div>
                                                        <div className="ev-score-row">
                                                            <span className="ev-score">Threat Score: {formatThreatScore(ev.event_details.threat_score)}</span>
                                                            <span className="ev-attack">{ev.event_details.attack_type || 'Activity'}</span>
                                                        </div>
                                                    </div>
                                                ) : null}

                                                {ev.notes && (
                                                    <div className="ev-notes">
                                                        <em>{ev.notes}</em>
                                                    </div>
                                                )}

                                                <div className="ev-footer">
                                                    <span className="ev-time">
                                                        {new Date(ev.added_at).toLocaleString()}
                                                    </span>
                                                    {ev.event_details && (
                                                        <button
                                                            type="button"
                                                            className="btn-ev-inspect"
                                                            onClick={() => {
                                                                if (onSelectEvent) onSelectEvent(ev.event_details);
                                                                setSelectedCaseForView(null);
                                                            }}
                                                        >
                                                            Inspect in Timeline
                                                        </button>
                                                    )}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>

                            {/* Add Note Section */}
                            <div className="cd-section">
                                <div className="cd-section-title">
                                    <MessageSquare className="w-3.5 h-3.5 text-emerald-400" />
                                    <span>Append Investigation Log Note</span>
                                </div>
                                <div className="modal-note-box">
                                    <textarea
                                        rows={2}
                                        value={modalNote}
                                        onChange={e => setModalNote(e.target.value)}
                                        placeholder="Add timestamped forensic note to case..."
                                        className="note-textarea"
                                    />
                                    <button
                                        type="button"
                                        className="btn-add-modal-note"
                                        disabled={!modalNote.trim() || addingModalNote}
                                        onClick={handleAddModalNote}
                                    >
                                        {addingModalNote ? 'Adding...' : 'Add Note'}
                                    </button>
                                </div>
                            </div>
                        </div>

                        {/* Modal Footer Actions */}
                        <div className="cm-modal-actions cd-footer-actions">
                            <button
                                type="button"
                                className="btn-export-pdf"
                                onClick={() => handleExportCasePDF(selectedCaseForView)}
                                title="Download official PDF forensic report"
                            >
                                <Download className="w-3.5 h-3.5 mr-1" /> Export PDF Report
                            </button>
                            <button
                                type="button"
                                className="btn-export-json"
                                onClick={() => handleExportCaseJSON(selectedCaseForView)}
                                title="Download JSON forensic dataset"
                            >
                                <FileText className="w-3.5 h-3.5 mr-1" /> Download JSON
                            </button>
                            <button
                                type="button"
                                className="btn-copy-summary"
                                onClick={() => handleCopyCaseText(selectedCaseForView)}
                                title="Copy text summary to clipboard"
                            >
                                <Clipboard className="w-3.5 h-3.5 mr-1" /> Copy Summary
                            </button>
                            <button
                                type="button"
                                className="btn-delete-case"
                                onClick={() => handleDeleteCase(selectedCaseForView.id)}
                                title="Permanently delete this case"
                            >
                                <Trash2 className="w-3.5 h-3.5 mr-1" /> Delete Case
                            </button>
                            <button
                                type="button"
                                className="btn-cancel"
                                onClick={() => setSelectedCaseForView(null)}
                            >
                                Close
                            </button>
                        </div>
                    </div>
                </div>,
                document.body
            )}
        </div>
    );
};

export default CaseManagement;

import React, { useState, useEffect } from 'react';
import { Plus, Trash2, Play, Clock, Zap, ChevronDown, AlertCircle } from 'lucide-react';
import axios from 'axios';
import './QueryBuilder.css';

const FIELDS = [
    { label: 'Source IP', value: 'src_ip', type: 'text', placeholder: 'e.g. 192.168.1.1' },
    { label: 'Source Port', value: 'src_port', type: 'number', placeholder: 'e.g. 4444' },
    { label: 'Destination IP', value: 'dst_ip', type: 'text', placeholder: 'e.g. 10.0.0.1' },
    { label: 'Destination Port', value: 'dst_port', type: 'number', placeholder: 'e.g. 22' },
    { label: 'Protocol', value: 'protocol', type: 'select', options: ['SSH', 'HTTP', 'FTP', 'SMTP', 'TCP', 'UDP'] },
    { label: 'Threat Score', value: 'threat_score', type: 'number', placeholder: 'e.g. 80' },
    { label: 'Threat Level', value: 'threat_level', type: 'select', options: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
    { label: 'Attack Type', value: 'attack_type', type: 'text', placeholder: 'e.g. SQL Injection' },
    { label: 'Payload Content', value: 'payload_content', type: 'text', placeholder: 'e.g. UNION SELECT' },
    { label: 'Timestamp', value: 'timestamp', type: 'text', placeholder: 'e.g. 24h' },
];

const OPERATORS = {
    text: [
        { label: 'Equals', value: 'equals' },
        { label: 'Not Equals', value: 'not_equals' },
        { label: 'Contains', value: 'contains' },
        { label: 'Not Contains', value: 'not_contains' },
        { label: 'In List', value: 'in_list' },
    ],
    number: [
        { label: 'Equals', value: 'equals' },
        { label: 'Greater Than', value: 'greater_than' },
        { label: 'Less Than', value: 'less_than' },
        { label: 'Between', value: 'between' },
    ],
    select: [
        { label: 'Equals', value: 'equals' },
        { label: 'Not Equals', value: 'not_equals' },
    ],
};

const TEMPLATES = [
    {
        label: 'All HIGH threats in 24h',
        icon: '🔴',
        desc: 'High-severity events in last 24 hours',
        logic: 'AND',
        conditions: [
            { field: 'threat_level', operator: 'equals', value: 'HIGH' },
            { field: 'timestamp', operator: 'greater_than', value: '24h' },
        ]
    },
    {
        label: 'SSH Brute Force',
        icon: '🔑',
        desc: 'SSH attacks with score > 80',
        logic: 'AND',
        conditions: [
            { field: 'protocol', operator: 'equals', value: 'SSH' },
            { field: 'threat_score', operator: 'greater_than', value: '80' },
        ]
    },
    {
        label: 'Port scans targeting h2',
        icon: '📡',
        desc: 'TCP traffic to HTTP honeypot',
        logic: 'AND',
        conditions: [
            { field: 'protocol', operator: 'equals', value: 'TCP' },
            { field: 'dst_port', operator: 'equals', value: '80' },
        ]
    },
    {
        label: 'SQL Injection Attempts',
        icon: '💉',
        desc: 'Payload containing SQL patterns',
        logic: 'AND',
        conditions: [
            { field: 'attack_type', operator: 'contains', value: 'SQL' },
            { field: 'threat_score', operator: 'greater_than', value: '60' },
        ]
    },
    {
        label: 'Critical Threats (Any)',
        icon: '⚠️',
        desc: 'Any CRITICAL level event',
        logic: 'OR',
        conditions: [
            { field: 'threat_level', operator: 'equals', value: 'CRITICAL' },
        ]
    },
];

const LOGIC_MODES = [
    { label: 'AND', desc: 'Match ALL conditions', value: 'AND' },
    { label: 'OR', desc: 'Match ANY condition', value: 'OR' },
    { label: 'NOT', desc: 'Exclude ALL matches', value: 'NOT' },
];

const QueryBuilder = ({ onSearch, loading }) => {
    const [logic, setLogic] = useState('AND');
    const [history, setHistory] = useState([]);
    const [conditions, setConditions] = useState([
        { field: 'threat_level', operator: 'equals', value: 'HIGH' }
    ]);
    const [validationError, setValidationError] = useState('');
    const [showHistory, setShowHistory] = useState(false);

    useEffect(() => { fetchHistory(); }, []);

    const fetchHistory = async () => {
        try {
            const response = await axios.get('/api/v1/hunting/history');
            setHistory(response.data || []);
        } catch (err) {
            // graceful — history is non-critical
        }
    };

    const getFieldMeta = (fieldValue) => FIELDS.find(f => f.value === fieldValue) || FIELDS[0];

    const getOperators = (fieldValue) => {
        const meta = getFieldMeta(fieldValue);
        return OPERATORS[meta.type] || OPERATORS.text;
    };

    const addCondition = () => {
        setConditions([...conditions, { field: 'src_ip', operator: 'equals', value: '' }]);
        setValidationError('');
    };

    const removeCondition = (index) => {
        if (conditions.length === 1) return;
        setConditions(conditions.filter((_, i) => i !== index));
        setValidationError('');
    };

    const updateCondition = (index, updates) => {
        const newConditions = [...conditions];
        const updated = { ...newConditions[index], ...updates };
        // If field type changed, reset operator to first valid one
        if (updates.field) {
            const ops = getOperators(updates.field);
            updated.operator = ops[0].value;
            updated.value = '';
        }
        newConditions[index] = updated;
        setConditions(newConditions);
        setValidationError('');
    };

    const validate = () => {
        for (const cond of conditions) {
            if (!cond.value || String(cond.value).trim() === '') {
                setValidationError('All conditions must have a value.');
                return false;
            }
        }
        return true;
    };

    const handleExecute = () => {
        if (!validate()) return;
        onSearch({
            logic,
            conditions: conditions.map(c => ({
                ...c,
                value: c.field === 'threat_score' || c.field === 'src_port' || c.field === 'dst_port'
                    ? parseFloat(c.value) || c.value
                    : c.value
            }))
        });
        setTimeout(fetchHistory, 1500);
    };

    const applyTemplate = (tpl) => {
        setLogic(tpl.logic);
        setConditions(tpl.conditions.map(c => ({ ...c })));
        setValidationError('');
    };

    const loadFromHistory = (item) => {
        try {
            const query = JSON.parse(item.query_json);
            setLogic(query.logic || 'AND');
            setConditions(query.conditions || []);
            setValidationError('');
        } catch (err) { /* ignore */ }
    };

    return (
        <div className="query-builder">
            {/* Logic Toggle */}
            <div className="qb-section">
                <div className="qb-label">Logic Mode</div>
                <div className="logic-toggle">
                    {LOGIC_MODES.map(m => (
                        <button
                            key={m.value}
                            className={`logic-btn ${logic === m.value ? 'active' : ''}`}
                            onClick={() => setLogic(m.value)}
                            title={m.desc}
                        >
                            {m.label}
                        </button>
                    ))}
                </div>
            </div>

            {/* Conditions */}
            <div className="qb-section">
                <div className="qb-label">Filter Conditions</div>
                <div className="conditions-list">
                    {conditions.map((cond, index) => {
                        const fieldMeta = getFieldMeta(cond.field);
                        const operators = getOperators(cond.field);
                        return (
                            <div key={index} className="condition-row">
                                <div className="condition-index">{index + 1}</div>
                                <div className="condition-fields">
                                    <select
                                        className="cond-select field-select"
                                        value={cond.field}
                                        onChange={(e) => updateCondition(index, { field: e.target.value })}
                                    >
                                        {FIELDS.map(f => (
                                            <option key={f.value} value={f.value}>{f.label}</option>
                                        ))}
                                    </select>

                                    <select
                                        className="cond-select op-select"
                                        value={cond.operator}
                                        onChange={(e) => updateCondition(index, { operator: e.target.value })}
                                    >
                                        {operators.map(o => (
                                            <option key={o.value} value={o.value}>{o.label}</option>
                                        ))}
                                    </select>

                                    {fieldMeta.type === 'select' ? (
                                        <select
                                            className="cond-select val-select"
                                            value={cond.value}
                                            onChange={(e) => updateCondition(index, { value: e.target.value })}
                                        >
                                            <option value="">Select...</option>
                                            {fieldMeta.options.map(o => (
                                                <option key={o} value={o}>{o}</option>
                                            ))}
                                        </select>
                                    ) : (
                                        <input
                                            className="cond-input"
                                            type={fieldMeta.type === 'number' ? 'text' : 'text'}
                                            value={cond.value}
                                            placeholder={fieldMeta.placeholder || 'Value...'}
                                            onChange={(e) => updateCondition(index, { value: e.target.value })}
                                        />
                                    )}
                                </div>
                                <button
                                    className="btn-remove"
                                    onClick={() => removeCondition(index)}
                                    disabled={conditions.length === 1}
                                    title="Remove condition"
                                >
                                    <Trash2 className="w-3 h-3" />
                                </button>
                            </div>
                        );
                    })}
                </div>

                {validationError && (
                    <div className="validation-msg">
                        <AlertCircle className="w-3 h-3" />
                        {validationError}
                    </div>
                )}

                <div className="builder-actions">
                    <button className="btn-add" onClick={addCondition}>
                        <Plus className="w-3.5 h-3.5" /> Add Filter
                    </button>
                    <button
                        className={`btn-execute ${loading ? 'loading' : ''}`}
                        onClick={handleExecute}
                        disabled={loading}
                    >
                        <Play className="w-3.5 h-3.5" />
                        {loading ? 'Searching...' : 'Execute Query'}
                    </button>
                </div>
            </div>

            {/* Query Templates */}
            <div className="qb-section">
                <div className="qb-label">
                    <Zap className="w-3 h-3" /> Quick Templates
                </div>
                <div className="template-list">
                    {TEMPLATES.map((tpl, i) => (
                        <button key={i} className="template-item" onClick={() => applyTemplate(tpl)}>
                            <span className="tpl-icon">{tpl.icon}</span>
                            <div className="tpl-text">
                                <div className="tpl-label">{tpl.label}</div>
                                <div className="tpl-desc">{tpl.desc}</div>
                            </div>
                        </button>
                    ))}
                </div>
            </div>

            {/* Search History */}
            {history.length > 0 && (
                <div className="qb-section">
                    <div
                        className="qb-label clickable"
                        onClick={() => setShowHistory(h => !h)}
                    >
                        <Clock className="w-3 h-3" />
                        Recent Searches ({history.length})
                        <ChevronDown className={`w-3 h-3 ml-auto chevron ${showHistory ? 'open' : ''}`} />
                    </div>
                    {showHistory && (
                        <div className="history-list">
                            {history.slice(0, 8).map((h) => (
                                <button key={h.id} className="history-item" onClick={() => loadFromHistory(h)}>
                                    <span className="h-hits">{h.result_count ?? '?'} hits</span>
                                    <span className="h-time">{new Date(h.executed_at).toLocaleTimeString()}</span>
                                </button>
                            ))}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default QueryBuilder;

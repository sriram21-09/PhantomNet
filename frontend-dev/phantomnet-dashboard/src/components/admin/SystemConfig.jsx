import React, { useState, useEffect, useCallback } from 'react';
import { Settings, Save, RotateCcw, CheckCircle, XCircle, Shield, Server, BarChart3, Cpu } from 'lucide-react';

const API_BASE = 'http://localhost:8000/api/v1/admin';

const CONFIG_SCHEMA = {
    threat_detection: {
        label: 'Threat Detection',
        icon: Shield,
        fields: [
            { key: 'ml_threshold', label: 'ML Detection Threshold', type: 'range', min: 0, max: 1, step: 0.05 },
            { key: 'auto_response', label: 'Auto-Response', type: 'toggle' },
            { key: 'alert_email', label: 'Alert Email', type: 'text' },
            { key: 'alert_severity_filter', label: 'Min Alert Severity', type: 'select', options: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
        ],
    },
    honeypot: {
        label: 'Honeypot Settings',
        icon: Server,
        fields: [
            { key: 'deception_mode', label: 'Deception Mode', type: 'select', options: ['aggressive', 'balanced', 'stealth'] },
            { key: 'ssh_banner', label: 'SSH Banner', type: 'text' },
            { key: 'http_banner', label: 'HTTP Banner', type: 'text' },
            { key: 'max_interaction_time', label: 'Max Interaction (sec)', type: 'number' },
        ],
    },
    siem: {
        label: 'SIEM Integration',
        icon: BarChart3,
        fields: [
            { key: 'siem_type', label: 'SIEM Type', type: 'select', options: ['none', 'splunk', 'elasticsearch', 'qradar', 'custom'] },
            { key: 'siem_endpoint', label: 'SIEM Endpoint URL', type: 'text' },
            { key: 'siem_export_frequency', label: 'Export Frequency (sec)', type: 'number' },
        ],
    },
    performance: {
        label: 'Performance',
        icon: Cpu,
        fields: [
            { key: 'db_pool_size', label: 'DB Pool Size', type: 'number' },
            { key: 'cache_ttl', label: 'Cache TTL (sec)', type: 'number' },
            { key: 'log_retention_days', label: 'Log Retention (days)', type: 'number' },
        ],
    },
};

const SystemConfig = () => {
    const [config, setConfig] = useState({});
    const [original, setOriginal] = useState({});
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [success, setSuccess] = useState('');
    const [error, setError] = useState('');
    const [activeSection, setActiveSection] = useState('threat_detection');

    const getHeaders = () => ({
        'Content-Type': 'application/json',
        Authorization: `Bearer ${localStorage.getItem('admin_token')}`,
    });

    const fetchConfig = useCallback(async () => {
        try {
            const res = await fetch(`${API_BASE}/config`, { headers: getHeaders() });
            const data = await res.json();
            setConfig(data.config || {});
            setOriginal(JSON.parse(JSON.stringify(data.config || {})));
        } catch (err) {
            setError('Failed to load configuration');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchConfig(); }, [fetchConfig]);

    const getValue = (category, key) => {
        return config[category]?.[key]?.value || '';
    };

    const setValue = (category, key, value) => {
        setConfig(prev => ({
            ...prev,
            [category]: {
                ...prev[category],
                [key]: { ...prev[category]?.[key], value },
            },
        }));
    };

    const hasChanges = (category) => {
        return JSON.stringify(config[category]) !== JSON.stringify(original[category]);
    };

    const saveSection = async (category) => {
        setSaving(true);
        setError('');
        try {
            const fields = CONFIG_SCHEMA[category].fields;
            for (const field of fields) {
                const val = getValue(category, field.key);
                await fetch(`${API_BASE}/config`, {
                    method: 'PUT',
                    headers: getHeaders(),
                    body: JSON.stringify({ key: field.key, value: String(val), category }),
                });
            }
            setOriginal(prev => ({ ...prev, [category]: JSON.parse(JSON.stringify(config[category])) }));
            setSuccess(`${CONFIG_SCHEMA[category].label} saved successfully`);
            setTimeout(() => setSuccess(''), 3000);
        } catch (err) {
            setError('Failed to save configuration');
        } finally {
            setSaving(false);
        }
    };

    const resetSection = (category) => {
        setConfig(prev => ({
            ...prev,
            [category]: JSON.parse(JSON.stringify(original[category] || {})),
        }));
    };

    const renderField = (category, field) => {
        const value = getValue(category, field.key);

        switch (field.type) {
            case 'toggle':
                return (
                    <div className="toggle-switch" onClick={() => setValue(category, field.key, value === 'true' ? 'false' : 'true')}>
                        <div className={`toggle-track ${value === 'true' ? 'on' : 'off'}`}>
                            <div className="toggle-thumb" />
                        </div>
                        <span className={`toggle-label ${value === 'true' ? 'label-on' : 'label-off'}`}>
                            {value === 'true' ? 'ENABLED' : 'DISABLED'}
                        </span>
                    </div>
                );
            case 'select':
                return (
                    <select value={value} onChange={(e) => setValue(category, field.key, e.target.value)} className="config-select">
                        {field.options.map(opt => <option key={opt} value={opt}>{opt.toUpperCase()}</option>)}
                    </select>
                );
            case 'range':
                return (
                    <div className="range-control">
                        <input
                            type="range"
                            min={field.min}
                            max={field.max}
                            step={field.step}
                            value={value || 0.5}
                            onChange={(e) => setValue(category, field.key, e.target.value)}
                            className="config-range"
                        />
                        <span className="range-value">{value || 0.5}</span>
                    </div>
                );
            case 'number':
                return (
                    <input
                        type="number"
                        value={value}
                        onChange={(e) => setValue(category, field.key, e.target.value)}
                        className="config-input"
                    />
                );
            default:
                return (
                    <input
                        type="text"
                        value={value}
                        onChange={(e) => setValue(category, field.key, e.target.value)}
                        className="config-input"
                    />
                );
        }
    };

    if (loading) return <div className="tab-loading"><div className="spinner" /><span>Loading configuration...</span></div>;

    return (
        <div className="system-config">
            {success && <div className="toast-success"><CheckCircle size={14} /> {success}</div>}
            {error && <div className="toast-error"><XCircle size={14} /> {error}</div>}

            <div className="config-layout">
                <div className="config-nav">
                    {Object.entries(CONFIG_SCHEMA).map(([key, section]) => {
                        const Icon = section.icon;
                        return (
                            <button
                                key={key}
                                className={`config-nav-btn ${activeSection === key ? 'active' : ''} ${hasChanges(key) ? 'has-changes' : ''}`}
                                onClick={() => setActiveSection(key)}
                            >
                                <Icon size={14} />
                                <span>{section.label}</span>
                                {hasChanges(key) && <span className="change-dot" />}
                            </button>
                        );
                    })}
                </div>

                <div className="config-panel">
                    {Object.entries(CONFIG_SCHEMA).filter(([key]) => key === activeSection).map(([category, section]) => {
                        const Icon = section.icon;
                        return (
                            <div key={category} className="config-section">
                                <div className="section-header">
                                    <h4><Icon size={14} /> {section.label.toUpperCase()}</h4>
                                    <div className="section-actions">
                                        <button
                                            className="reset-btn"
                                            onClick={() => resetSection(category)}
                                            disabled={!hasChanges(category)}
                                        >
                                            <RotateCcw size={12} /> RESET
                                        </button>
                                        <button
                                            className="save-btn"
                                            onClick={() => saveSection(category)}
                                            disabled={!hasChanges(category) || saving}
                                        >
                                            <Save size={12} /> {saving ? 'SAVING...' : 'SAVE'}
                                        </button>
                                    </div>
                                </div>
                                <div className="config-fields">
                                    {section.fields.map(field => (
                                        <div className="config-field" key={field.key}>
                                            <label>{field.label}</label>
                                            {renderField(category, field)}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>
        </div>
    );
};

export default SystemConfig;

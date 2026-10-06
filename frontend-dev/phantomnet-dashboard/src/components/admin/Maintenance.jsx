import React, { useState, useCallback, useRef } from 'react';
import { Database, Download, Upload, Zap, Trash2, CheckCircle, XCircle, Clock, HardDrive, TriangleAlert, FileText, X } from 'lucide-react';
import { adminFetch, safeParseJson } from '../../utils/adminFetch';

const API_BASE = '/api/v1/admin';

const Maintenance = () => {
    const [backups, setBackups] = useState([]);
    const [backupsLoaded, setBackupsLoaded] = useState(false);
    const [loading, setLoading] = useState({});
    const [results, setResults] = useState({});
    const [purgeDays, setPurgeDays] = useState(30);
    const [showPurgeConfirm, setShowPurgeConfirm] = useState(false);

    // Restore state
    const [selectedFile, setSelectedFile] = useState(null);
    const [selectedHistoryBackup, setSelectedHistoryBackup] = useState(null);
    const [showRestoreConfirm, setShowRestoreConfirm] = useState(false);
    const [dragActive, setDragActive] = useState(false);
    const fileInputRef = useRef(null);

    const setResult = (key, type, message) => {
        setResults(prev => ({ ...prev, [key]: { type, message } }));
        setTimeout(() => setResults(prev => { const n = { ...prev }; delete n[key]; return n; }), 8000);
    };

    const fetchBackups = useCallback(async () => {
        try {
            const res = await adminFetch(`${API_BASE}/backups`);
            const data = await safeParseJson(res, 'Failed to load backup history');
            setBackups(data.backups || []);
            setBackupsLoaded(true);
        } catch (err) {
            setResult('backups', 'error', err.message || 'Failed to load backup history');
        }
    }, []);

    const handleBackup = async () => {
        setLoading(p => ({ ...p, backup: true }));
        try {
            const res = await adminFetch(`${API_BASE}/backup`, { method: 'POST' });
            const data = await safeParseJson(res, 'Backup failed');
            setResult('backup', 'success', `Backup created: ${data.backup_file} (${data.size_mb} MB)`);
            fetchBackups();
        } catch (err) {
            setResult('backup', 'error', err.message);
        } finally {
            setLoading(p => ({ ...p, backup: false }));
        }
    };

    const handleFileSelect = (e) => {
        const file = e.target.files?.[0];
        if (file) {
            if (!file.name.endsWith('.json')) {
                setResult('restore', 'error', 'Invalid file type. Please select a JSON backup file (.json).');
                return;
            }
            setSelectedFile(file);
            setSelectedHistoryBackup(null);
        }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        setDragActive(false);
        const file = e.dataTransfer.files?.[0];
        if (file) {
            if (!file.name.endsWith('.json')) {
                setResult('restore', 'error', 'Invalid file type. Please select a JSON backup file (.json).');
                return;
            }
            setSelectedFile(file);
            setSelectedHistoryBackup(null);
        }
    };

    const promptRestoreFile = () => {
        if (!selectedFile) return;
        setSelectedHistoryBackup(null);
        setShowRestoreConfirm(true);
    };

    const promptRestoreHistory = (filename) => {
        setSelectedHistoryBackup(filename);
        setSelectedFile(null);
        setShowRestoreConfirm(true);
    };

    const handleRestore = async () => {
        setShowRestoreConfirm(false);
        setLoading(p => ({ ...p, restore: true }));
        try {
            const formData = new FormData();
            if (selectedFile) {
                formData.append('file', selectedFile);
            } else if (selectedHistoryBackup) {
                formData.append('filename', selectedHistoryBackup);
            } else {
                throw new Error('No backup source selected');
            }

            const res = await adminFetch(`${API_BASE}/restore`, {
                method: 'POST',
                body: formData,
            });
            const data = await safeParseJson(res, 'Database restore failed');

            const countsObj = data.restored_counts || data.restored;
            const restoredCounts = countsObj
                ? Object.entries(countsObj).map(([k, v]) => `${k}: ${v}`).join(', ')
                : '';
            const successMsg = `${data.message || 'Database restored'}${restoredCounts ? ` (${restoredCounts})` : ''}`;
            setResult('restore', 'success', successMsg);
            setSelectedFile(null);
            setSelectedHistoryBackup(null);
            if (fileInputRef.current) fileInputRef.current.value = '';
        } catch (err) {
            setResult('restore', 'error', err.message);
        } finally {
            setLoading(p => ({ ...p, restore: false }));
        }
    };

    const handleVacuum = async () => {
        setLoading(p => ({ ...p, vacuum: true }));
        try {
            const res = await adminFetch(`${API_BASE}/vacuum`, { method: 'POST' });
            const data = await safeParseJson(res, 'Vacuum failed');
            setResult('vacuum', 'success', data.message || 'Database optimized successfully');
        } catch (err) {
            setResult('vacuum', 'error', err.message);
        } finally {
            setLoading(p => ({ ...p, vacuum: false }));
        }
    };

    const handlePurge = async () => {
        setShowPurgeConfirm(false);
        setLoading(p => ({ ...p, purge: true }));
        try {
            const res = await adminFetch(`${API_BASE}/events/old?days=${purgeDays}`, {
                method: 'DELETE',
            });
            const data = await safeParseJson(res, 'Purge failed');
            setResult('purge', 'success',
                `Deleted ${data.deleted?.total || 0} records (${data.deleted?.packet_logs ?? 0} packets, ${data.deleted?.events ?? 0} events, ${data.deleted?.alerts ?? 0} alerts)`
            );
        } catch (err) {
            setResult('purge', 'error', err.message);
        } finally {
            setLoading(p => ({ ...p, purge: false }));
        }
    };

    const ResultBanner = ({ id }) => {
        const r = results[id];
        if (!r) return null;
        return (
            <div className={`maint-result ${r.type === 'success' ? 'result-success' : 'result-error'}`}>
                {r.type === 'success' ? <CheckCircle size={14} /> : <XCircle size={14} />}
                {r.message}
            </div>
        );
    };

    return (
        <div className="maintenance-panel">
            <div className="maint-grid">
                {/* Backup Card */}
                <div className="maint-card">
                    <div className="maint-card-header">
                        <h4><Download size={14} /> DATABASE BACKUP</h4>
                    </div>
                    <p className="maint-desc">Create a full database backup. Backup files are stored securely with SHA-256 integrity validation.</p>
                    <ResultBanner id="backup" />
                    <button
                        className="maint-action-btn btn-primary"
                        onClick={handleBackup}
                        disabled={loading.backup}
                    >
                        {loading.backup ? (
                            <><div className="spinner-sm" /> CREATING BACKUP...</>
                        ) : (
                            <><Database size={14} /> CREATE BACKUP</>
                        )}
                    </button>

                    {!backupsLoaded && (
                        <button className="maint-link-btn" onClick={fetchBackups}>View backup history</button>
                    )}
                    <ResultBanner id="backups" />
                    {backupsLoaded && backups.length > 0 && (
                        <div className="backup-history">
                            <h5><Clock size={12} /> BACKUP HISTORY</h5>
                            <div className="backup-list">
                                {backups.slice(0, 5).map(b => (
                                    <div className="backup-item" key={b.filename}>
                                        <HardDrive size={12} />
                                        <span className="backup-name" title={b.filename}>{b.filename}</span>
                                        <span className="backup-size">{b.size_mb} MB</span>
                                        <span className="backup-date">{new Date(b.created_at).toLocaleDateString()}</span>
                                        <button
                                            className="backup-restore-btn"
                                            onClick={() => promptRestoreHistory(b.filename)}
                                            title="Restore this backup"
                                        >
                                            RESTORE
                                        </button>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                    {backupsLoaded && backups.length === 0 && (
                        <div className="no-backups">No backups yet</div>
                    )}
                </div>

                {/* Restore Card */}
                <div className="maint-card">
                    <div className="maint-card-header">
                        <h4><Upload size={14} /> DATABASE RESTORE</h4>
                    </div>
                    <p className="maint-desc">Restore database from a validated backup archive (.json). Existing user passwords will be preserved.</p>
                    <ResultBanner id="restore" />

                    <input
                        type="file"
                        ref={fileInputRef}
                        accept=".json"
                        style={{ display: 'none' }}
                        onChange={handleFileSelect}
                    />

                    {!selectedFile ? (
                        <div
                            className={`restore-dropzone ${dragActive ? 'drag-active' : ''}`}
                            onClick={() => fileInputRef.current?.click()}
                            onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
                            onDragLeave={() => setDragActive(false)}
                            onDrop={handleDrop}
                        >
                            <Upload size={24} />
                            <span>Upload backup file (.json)</span>
                            <span className="dz-hint">Drag & drop or click to browse</span>
                        </div>
                    ) : (
                        <div className="selected-file-box">
                            <div className="selected-file-info">
                                <FileText size={16} />
                                <div>
                                    <div><strong>{selectedFile.name}</strong></div>
                                    <div style={{ fontSize: '0.62rem', color: '#888' }}>
                                        {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB
                                    </div>
                                </div>
                            </div>
                            <button
                                className="action-btn delete-btn"
                                onClick={() => {
                                    setSelectedFile(null);
                                    if (fileInputRef.current) fileInputRef.current.value = '';
                                }}
                                title="Remove file"
                            >
                                <X size={14} />
                            </button>
                        </div>
                    )}

                    {selectedFile && (
                        <button
                            className="maint-action-btn btn-accent"
                            onClick={promptRestoreFile}
                            disabled={loading.restore}
                            style={{ marginTop: '0.5rem' }}
                        >
                            {loading.restore ? (
                                <><div className="spinner-sm" /> RESTORING...</>
                            ) : (
                                <><Upload size={14} /> PROCEED TO RESTORE</>
                            )}
                        </button>
                    )}

                    <div className="restore-warning">
                        <TriangleAlert size={14} />
                        Restore modifies system configuration, policies, and nodes. Create a fresh backup first.
                    </div>
                </div>

                {/* Vacuum Card */}
                <div className="maint-card">
                    <div className="maint-card-header">
                        <h4><Zap size={14} /> VACUUM & OPTIMIZE</h4>
                    </div>
                    <p className="maint-desc">Run VACUUM to reclaim storage space, rebuild indexes, and update statistics for optimal performance.</p>
                    <ResultBanner id="vacuum" />
                    <div className="vacuum-ops">
                        <div className="vac-op">
                            <span className="vac-icon">🔧</span>
                            <div>
                                <strong>VACUUM</strong>
                                <span>Reclaim unused space</span>
                            </div>
                        </div>
                        <div className="vac-op">
                            <span className="vac-icon">📊</span>
                            <div>
                                <strong>Rebuild Indexes</strong>
                                <span>Optimize query performance</span>
                            </div>
                        </div>
                        <div className="vac-op">
                            <span className="vac-icon">📈</span>
                            <div>
                                <strong>Update Stats</strong>
                                <span>Refresh query planner data</span>
                            </div>
                        </div>
                    </div>
                    <button
                        className="maint-action-btn btn-accent"
                        onClick={handleVacuum}
                        disabled={loading.vacuum}
                    >
                        {loading.vacuum ? (
                            <><div className="spinner-sm" /> OPTIMIZING...</>
                        ) : (
                            <><Zap size={14} /> RUN OPTIMIZATION</>
                        )}
                    </button>
                </div>

                {/* Purge Card */}
                <div className="maint-card">
                    <div className="maint-card-header">
                        <h4><Trash2 size={14} /> CLEAR OLD DATA</h4>
                    </div>
                    <p className="maint-desc">Delete old events, alerts, and logs older than the specified number of days.</p>
                    <ResultBanner id="purge" />
                    <div className="purge-control">
                        <label>Delete events older than:</label>
                        <div className="purge-input-row">
                            <input
                                type="number"
                                value={purgeDays}
                                onChange={(e) => setPurgeDays(Math.max(1, parseInt(e.target.value) || 30))}
                                min={1}
                                className="purge-input"
                            />
                            <span className="purge-unit">days</span>
                        </div>
                        <div className="purge-presets">
                            {[7, 30, 60, 90].map(d => (
                                <button key={d} className={`preset-btn ${purgeDays === d ? 'active' : ''}`} onClick={() => setPurgeDays(d)}>
                                    {d}d
                                </button>
                            ))}
                        </div>
                    </div>
                    <button
                        className="maint-action-btn btn-danger"
                        onClick={() => setShowPurgeConfirm(true)}
                        disabled={loading.purge}
                    >
                        {loading.purge ? (
                            <><div className="spinner-sm" /> PURGING...</>
                        ) : (
                            <><Trash2 size={14} /> PURGE OLD DATA</>
                        )}
                    </button>
                </div>
            </div>

            {/* Restore Confirmation Dialog */}
            {showRestoreConfirm && (
                <div className="modal-overlay" onClick={() => setShowRestoreConfirm(false)}>
                    <div className="modal-card confirm-card" onClick={e => e.stopPropagation()}>
                        <div className="confirm-icon" style={{ color: '#f77f00' }}>⚠️</div>
                        <h3>CONFIRM DATABASE RESTORE</h3>
                        <p>
                            You are about to restore the database from:
                            <br />
                            <strong style={{ color: '#4cc9f0', wordBreak: 'break-all' }}>
                                {selectedFile ? selectedFile.name : selectedHistoryBackup}
                            </strong>
                        </p>
                        <p className="confirm-warning">
                            This will overwrite system settings, honeypot nodes, and policies with the archive contents.
                            Existing user accounts and password hashes will be preserved.
                        </p>
                        <div className="confirm-actions">
                            <button className="cancel-btn" onClick={() => setShowRestoreConfirm(false)}>CANCEL</button>
                            <button className="danger-btn" onClick={handleRestore} style={{ background: '#f77f00', color: '#000' }}>
                                CONFIRM RESTORE
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Purge Confirmation */}
            {showPurgeConfirm && (
                <div className="modal-overlay" onClick={() => setShowPurgeConfirm(false)}>
                    <div className="modal-card confirm-card" onClick={e => e.stopPropagation()}>
                        <div className="confirm-icon">🗑️</div>
                        <h3>PURGE OLD DATA</h3>
                        <p>This will permanently delete all events, alerts, and logs older than <strong>{purgeDays} days</strong>.</p>
                        <p className="confirm-warning">This action cannot be undone.</p>
                        <div className="confirm-actions">
                            <button className="cancel-btn" onClick={() => setShowPurgeConfirm(false)}>CANCEL</button>
                            <button className="danger-btn" onClick={handlePurge}>PURGE</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Maintenance;

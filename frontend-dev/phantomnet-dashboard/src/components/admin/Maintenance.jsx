import React, { useState, useCallback } from 'react';
import { Database, Download, Upload, Zap, Trash2, CheckCircle, XCircle, Clock, HardDrive, TriangleAlert } from 'lucide-react';

const API_BASE = 'http://localhost:8000/api/v1/admin';

const Maintenance = () => {
    const [backups, setBackups] = useState([]);
    const [backupsLoaded, setBackupsLoaded] = useState(false);
    const [loading, setLoading] = useState({});
    const [results, setResults] = useState({});
    const [purgeDays, setPurgeDays] = useState(30);
    const [showPurgeConfirm, setShowPurgeConfirm] = useState(false);

    const getHeaders = () => ({
        'Content-Type': 'application/json',
        Authorization: `Bearer ${localStorage.getItem('admin_token')}`,
    });

    const setResult = (key, type, message) => {
        setResults(prev => ({ ...prev, [key]: { type, message } }));
        setTimeout(() => setResults(prev => { const n = { ...prev }; delete n[key]; return n; }), 5000);
    };

    const fetchBackups = useCallback(async () => {
        try {
            const res = await fetch(`${API_BASE}/backups`, { headers: getHeaders() });
            const data = await res.json();
            setBackups(data.backups || []);
            setBackupsLoaded(true);
        } catch (err) {
            setResult('backups', 'error', 'Failed to load backup history');
        }
    }, []);

    const handleBackup = async () => {
        setLoading(p => ({ ...p, backup: true }));
        try {
            const res = await fetch(`${API_BASE}/backup`, { method: 'POST', headers: getHeaders() });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Backup failed');
            setResult('backup', 'success', `Backup created: ${data.backup_file} (${data.size_mb} MB)`);
            fetchBackups();
        } catch (err) {
            setResult('backup', 'error', err.message);
        } finally {
            setLoading(p => ({ ...p, backup: false }));
        }
    };

    const handleVacuum = async () => {
        setLoading(p => ({ ...p, vacuum: true }));
        try {
            const res = await fetch(`${API_BASE}/vacuum`, { method: 'POST', headers: getHeaders() });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Vacuum failed');
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
            const res = await fetch(`${API_BASE}/events/old?days=${purgeDays}`, {
                method: 'DELETE', headers: getHeaders(),
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Purge failed');
            setResult('purge', 'success',
                `Deleted ${data.deleted?.total || 0} records (${data.deleted?.packet_logs} packets, ${data.deleted?.events} events, ${data.deleted?.alerts} alerts)`
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
                    <p className="maint-desc">Create a full database backup. Backup files are stored in the <code>backups/</code> directory.</p>
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
                    {backupsLoaded && backups.length > 0 && (
                        <div className="backup-history">
                            <h5><Clock size={12} /> BACKUP HISTORY</h5>
                            <div className="backup-list">
                                {backups.slice(0, 5).map(b => (
                                    <div className="backup-item" key={b.filename}>
                                        <HardDrive size={12} />
                                        <span className="backup-name">{b.filename}</span>
                                        <span className="backup-size">{b.size_mb} MB</span>
                                        <span className="backup-date">{new Date(b.created_at).toLocaleDateString()}</span>
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
                    <p className="maint-desc">Restore database from a previous backup. Select a backup file to restore.</p>
                    <div className="restore-dropzone">
                        <Upload size={24} />
                        <span>Upload backup file (.db)</span>
                        <span className="dz-hint">or select from backup history</span>
                    </div>
                    <div className="restore-warning">
                        <TriangleAlert size={12} />
                        Restore will overwrite the current database. Create a backup first.
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

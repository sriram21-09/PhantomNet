import React, { useState, useEffect, useCallback } from 'react';
import { Navigate } from 'react-router-dom';
import { Shield, Users, Settings, Wrench, Server, Activity, Clock, Lock } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import UserManagement from '../components/admin/UserManagement';
import SystemConfig from '../components/admin/SystemConfig';
import Maintenance from '../components/admin/Maintenance';
import { adminFetch } from '../utils/adminFetch';
import '../Styles/pages/AdminPanel.css';

const API_BASE = '/api/v1/admin';

// Admin-only route guard
const AdminGuard = ({ children }) => {
    const { user, isAuthenticated, isLoading } = useAuth();

    if (isLoading) {
        return <div className="admin-loading"><div className="spinner" /><span>Authenticating...</span></div>;
    }

    if (!isAuthenticated) {
        return <Navigate to="/login" replace />;
    }

    if (user && user.role && user.role.toLowerCase() !== 'admin') {
        return (
            <div className="admin-login-page">
                <div className="login-card">
                    <div className="login-header">
                        <Lock size={24} />
                        <h2>ACCESS RESTRICTED</h2>
                        <p>Administrator privileges required to access this panel.</p>
                    </div>
                </div>
            </div>
        );
    }

    return children;
};

// System Overview Tab
const SystemOverview = () => {
    const [overview, setOverview] = useState(null);
    const [loading, setLoading] = useState(true);

    const fetchOverview = useCallback(async () => {
        try {
            const res = await adminFetch(`${API_BASE}/system-overview`);
            const data = await res.json();
            setOverview(data);
        } catch {
            // Ignore fetch error
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchOverview(); }, [fetchOverview]);

    if (loading) return <div className="tab-loading"><div className="spinner" /><span>Loading system overview...</span></div>;
    if (!overview) return <div className="tab-empty">Unable to fetch system information.</div>;

    return (
        <div className="overview-grid">
            {/* System Info */}
            <div className="overview-card">
                <h4><Server size={14} /> SYSTEM INFORMATION</h4>
                <div className="info-grid">
                    <div className="info-item"><label>VERSION:</label><span>{overview.system?.version}</span></div>
                    <div className="info-item"><label>STATUS:</label><span className="status-online">{overview.system?.uptime}</span></div>
                    <div className="info-item"><label>PYTHON:</label><span>{overview.system?.python_version}</span></div>
                    <div className="info-item"><label>DATABASE:</label><span>{overview.system?.db_type}</span></div>
                    <div className="info-item"><label>DB SIZE:</label><span>{overview.system?.db_size_mb} MB</span></div>
                </div>
            </div>

            {/* Resources */}
            <div className="overview-card">
                <h4><Activity size={14} /> RESOURCE USAGE</h4>
                <div className="resource-bars">
                    {[
                        { label: 'CPU', value: overview.resources?.cpu_percent || 0, warn: 80 },
                        { label: 'MEMORY', value: overview.resources?.memory_percent || 0, warn: 85 },
                        { label: 'DISK', value: overview.resources?.disk_percent || 0, warn: 90 },
                    ].map(r => (
                        <div className="res-item" key={r.label}>
                            <div className="res-header">
                                <span>{r.label}</span>
                                <span className={r.value > r.warn ? 'res-warn' : ''}>{r.value}%</span>
                            </div>
                            <div className="res-bar-bg">
                                <div
                                    className="res-bar-fill"
                                    style={{
                                        width: `${r.value}%`,
                                        background: r.value > r.warn ? 'linear-gradient(90deg, #f77f00, #ff0055)' : 'linear-gradient(90deg, #4cc9f0, #00ff41)'
                                    }}
                                />
                            </div>
                        </div>
                    ))}
                    <div className="res-detail">RAM: {overview.resources?.memory_used_gb} GB used</div>
                </div>
            </div>

            {/* Stats */}
            <div className="overview-card">
                <h4><Clock size={14} /> STATISTICS</h4>
                <div className="stat-boxes">
                    {[
                        { label: 'Events', value: overview.stats?.total_events || 0, icon: '📊' },
                        { label: 'Alerts', value: overview.stats?.total_alerts || 0, icon: '🚨' },
                        { label: 'Users', value: overview.stats?.total_users || 0, icon: '👤' },
                    ].map(s => (
                        <div className="stat-box" key={s.label}>
                            <span className="stat-icon">{s.icon}</span>
                            <div className="stat-value">{s.value.toLocaleString()}</div>
                            <div className="stat-label">{s.label}</div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Components */}
            <div className="overview-card">
                <h4><Shield size={14} /> COMPONENT STATUS</h4>
                <div className="component-list">
                    {(overview.components || []).map(c => (
                        <div className="comp-item" key={c.name}>
                            <span className={`comp-dot ${c.status === 'online' ? 'dot-online' : 'dot-offline'}`} />
                            <span className="comp-name">{c.name}</span>
                            <span className={`comp-status ${c.status === 'online' ? 'text-online' : 'text-offline'}`}>
                                {c.status.toUpperCase()}
                            </span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

const AdminPanel = () => {
    const [activeTab, setActiveTab] = useState('overview');
    const [adminUser, setAdminUser] = useState({ username: 'admin', role: 'Admin' });

    useEffect(() => {
        fetch(`${API_BASE}/me`, { credentials: 'include' })
            .then(res => res.ok ? res.json() : null)
            .then(data => {
                if (data) setAdminUser(data);
            })
            .catch(() => {});
    }, []);

    const handleLogout = async () => {
        try {
            await adminFetch(`${API_BASE}/logout`, { method: 'POST' });
        } catch {
            // Ignore error
        }
        window.location.reload();
    };

    const tabs = [
        { id: 'overview', label: 'System Overview', icon: Server },
        { id: 'users', label: 'User Management', icon: Users },
        { id: 'config', label: 'Configuration', icon: Settings },
        { id: 'maintenance', label: 'Maintenance', icon: Wrench },
    ];

    return (
        <AdminGuard>
            <div className="admin-panel-container">
                <div className="admin-header">
                    <div className="admin-header-left">
                        <div className="admin-badge"><Shield size={12} /> ADMIN_PANEL</div>
                        <h1 className="admin-title">System Administration</h1>
                        <p className="admin-subtitle">RBAC MANAGEMENT | CONFIGURATION | MAINTENANCE</p>
                    </div>
                    <div className="admin-header-right">
                        <div className="admin-user-info">
                            <span className="user-role-badge">{adminUser.role || 'Admin'}</span>
                            <span className="user-name">{adminUser.username || 'admin'}</span>
                        </div>
                        <button className="logout-btn" onClick={handleLogout}>LOGOUT</button>
                    </div>
                </div>

                <div className="admin-tabs">
                    {tabs.map(tab => {
                        const Icon = tab.icon;
                        return (
                            <button
                                key={tab.id}
                                className={`admin-tab ${activeTab === tab.id ? 'active' : ''}`}
                                onClick={() => setActiveTab(tab.id)}
                            >
                                <Icon size={14} />
                                <span>{tab.label}</span>
                            </button>
                        );
                    })}
                </div>

                <div className="admin-content">
                    {activeTab === 'overview' && <SystemOverview />}
                    {activeTab === 'users' && <UserManagement />}
                    {activeTab === 'config' && <SystemConfig />}
                    {activeTab === 'maintenance' && <Maintenance />}
                </div>
            </div>
        </AdminGuard>
    );
};

export default AdminPanel;

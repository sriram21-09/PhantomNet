import React, { useState, useEffect, useCallback } from 'react';
import { Shield, Users, Settings, Wrench, Server, Activity, Clock, Lock } from 'lucide-react';
import UserManagement from '../components/admin/UserManagement';
import SystemConfig from '../components/admin/SystemConfig';
import Maintenance from '../components/admin/Maintenance';
import '../Styles/pages/AdminPanel.css';

const API_BASE = 'http://localhost:8000/api/v1/admin';

// Admin-only route guard
const AdminGuard = ({ children }) => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [loginForm, setLoginForm] = useState({ username: '', password: '' });
    const [error, setError] = useState('');

    useEffect(() => {
        const token = localStorage.getItem('admin_token');
        if (token) {
            setIsAuthenticated(true);
        }
        setIsLoading(false);
    }, []);

    const handleLogin = async (e) => {
        e.preventDefault();
        setError('');
        try {
            const res = await fetch(`${API_BASE}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(loginForm),
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Login failed');
            localStorage.setItem('admin_token', data.access_token);
            localStorage.setItem('admin_user', JSON.stringify(data.user));
            setIsAuthenticated(true);
        } catch (err) {
            setError(err.message);
        }
    };

    if (isLoading) return <div className="admin-loading"><div className="spinner" /><span>Authenticating...</span></div>;

    if (!isAuthenticated) {
        return (
            <div className="admin-login-page">
                <div className="login-card">
                    <div className="login-header">
                        <Lock size={24} />
                        <h2>ADMIN ACCESS</h2>
                        <p>PhantomNet Control Panel</p>
                    </div>
                    <form onSubmit={handleLogin}>
                        <div className="form-group">
                            <label>USERNAME</label>
                            <input
                                type="text"
                                value={loginForm.username}
                                onChange={(e) => setLoginForm(p => ({ ...p, username: e.target.value }))}
                                placeholder="admin"
                                required
                            />
                        </div>
                        <div className="form-group">
                            <label>PASSWORD</label>
                            <input
                                type="password"
                                value={loginForm.password}
                                onChange={(e) => setLoginForm(p => ({ ...p, password: e.target.value }))}
                                placeholder="••••••••"
                                required
                            />
                        </div>
                        {error && <div className="login-error">{error}</div>}
                        <button type="submit" className="login-btn">AUTHENTICATE</button>
                    </form>
                    <div className="login-footer">Default: admin / admin123</div>
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
            const token = localStorage.getItem('admin_token');
            const res = await fetch(`${API_BASE}/system-overview`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            const data = await res.json();
            setOverview(data);
        } catch (err) {
            console.error('Failed to fetch overview:', err);
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

// Main Admin Panel
const AdminPanel = () => {
    const [activeTab, setActiveTab] = useState('overview');
    const adminUser = JSON.parse(localStorage.getItem('admin_user') || '{}');

    const handleLogout = () => {
        localStorage.removeItem('admin_token');
        localStorage.removeItem('admin_user');
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

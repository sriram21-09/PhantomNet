import React, { useState, useEffect, useCallback } from 'react';
import { Users, Plus, Edit, Trash2, X, CheckCircle, XCircle, Search } from 'lucide-react';
import { adminFetch } from '../../pages/AdminPanel';

const API_BASE = '/api/v1/admin';

const UserManagement = () => {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [editingUser, setEditingUser] = useState(null);
    const [deleteConfirm, setDeleteConfirm] = useState(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [formData, setFormData] = useState({ username: '', email: '', password: '', role: 'Viewer' });
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');



    const fetchUsers = useCallback(async () => {
        try {
            const res = await adminFetch(`${API_BASE}/users`);
            const data = await res.json();
            setUsers(data.users || []);
        } catch (err) {
            setError('Failed to fetch users');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchUsers(); }, [fetchUsers]);

    const handleCreate = async (e) => {
        e.preventDefault();
        setError('');
        try {
            const res = await adminFetch(`${API_BASE}/users`, {
                method: 'POST',
                body: JSON.stringify(formData),
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Failed');
            setSuccess(`User "${formData.username}" created`);
            setShowModal(false);
            setFormData({ username: '', email: '', password: '', role: 'Viewer' });
            fetchUsers();
            setTimeout(() => setSuccess(''), 3000);
        } catch (err) {
            setError(err.message);
        }
    };

    const handleUpdate = async (e) => {
        e.preventDefault();
        setError('');
        try {
            const body = {};
            if (formData.email) body.email = formData.email;
            if (formData.password) body.password = formData.password;
            if (formData.role) body.role = formData.role;
            if (formData.status) body.status = formData.status;

            const res = await adminFetch(`${API_BASE}/users/${editingUser.id}`, {
                method: 'PUT',
                body: JSON.stringify(body),
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Failed');
            setSuccess(`User "${editingUser.username}" updated`);
            setShowModal(false);
            setEditingUser(null);
            fetchUsers();
            setTimeout(() => setSuccess(''), 3000);
        } catch (err) {
            setError(err.message);
        }
    };

    const handleDelete = async (userId) => {
        try {
            const res = await adminFetch(`${API_BASE}/users/${userId}`, {
                method: 'DELETE',
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Failed');
            setSuccess('User deleted');
            setDeleteConfirm(null);
            fetchUsers();
            setTimeout(() => setSuccess(''), 3000);
        } catch (err) {
            setError(err.message);
        }
    };

    const openCreate = () => {
        setEditingUser(null);
        setFormData({ username: '', email: '', password: '', role: 'Viewer' });
        setError('');
        setShowModal(true);
    };

    const openEdit = (user) => {
        setEditingUser(user);
        setFormData({ username: user.username, email: user.email, password: '', role: user.role, status: user.status });
        setError('');
        setShowModal(true);
    };

    const filtered = users.filter(u =>
        u.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
        u.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
        u.role.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const getRoleBadge = (role) => {
        const styles = {
            Admin: 'badge-admin',
            Analyst: 'badge-analyst',
            Viewer: 'badge-viewer',
        };
        return styles[role] || 'badge-viewer';
    };

    if (loading) return <div className="tab-loading"><div className="spinner" /><span>Loading users...</span></div>;

    return (
        <div className="user-management">
            {success && <div className="toast-success"><CheckCircle size={14} /> {success}</div>}
            {error && <div className="toast-error"><XCircle size={14} /> {error}</div>}

            <div className="um-toolbar">
                <div className="search-box">
                    <Search size={14} />
                    <input
                        type="text"
                        placeholder="Search users..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                    />
                </div>
                <button className="create-btn" onClick={openCreate}>
                    <Plus size={14} /> CREATE USER
                </button>
            </div>

            <div className="users-table-wrapper">
                <table className="users-table">
                    <thead>
                        <tr>
                            <th>USERNAME</th>
                            <th>EMAIL</th>
                            <th>ROLE</th>
                            <th>STATUS</th>
                            <th>LAST LOGIN</th>
                            <th>ACTIONS</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filtered.length === 0 ? (
                            <tr><td colSpan="6" className="empty-row">No users found</td></tr>
                        ) : (
                            filtered.map(user => (
                                <tr key={user.id}>
                                    <td className="cell-username">
                                        <span className="user-avatar">{user.username[0].toUpperCase()}</span>
                                        {user.username}
                                    </td>
                                    <td className="cell-email">{user.email}</td>
                                    <td><span className={`role-badge ${getRoleBadge(user.role)}`}>{user.role}</span></td>
                                    <td>
                                        <span className={`status-pill ${user.status === 'active' ? 'pill-active' : 'pill-disabled'}`}>
                                            {user.status}
                                        </span>
                                    </td>
                                    <td className="cell-date">
                                        {user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}
                                    </td>
                                    <td className="cell-actions">
                                        <button className="action-btn edit-btn" onClick={() => openEdit(user)} title="Edit">
                                            <Edit size={13} />
                                        </button>
                                        <button
                                            className="action-btn delete-btn"
                                            onClick={() => setDeleteConfirm(user)}
                                            title="Delete"
                                            disabled={user.username === 'admin'}
                                        >
                                            <Trash2 size={13} />
                                        </button>
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>

            <div className="um-footer">{filtered.length} of {users.length} users</div>

            {/* Create/Edit Modal */}
            {showModal && (
                <div className="modal-overlay" onClick={() => setShowModal(false)}>
                    <div className="modal-card" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>{editingUser ? 'EDIT USER' : 'CREATE USER'}</h3>
                            <button className="close-btn" onClick={() => setShowModal(false)}><X size={16} /></button>
                        </div>
                        <form onSubmit={editingUser ? handleUpdate : handleCreate}>
                            {!editingUser && (
                                <div className="form-group">
                                    <label>USERNAME</label>
                                    <input
                                        type="text"
                                        value={formData.username}
                                        onChange={(e) => setFormData(p => ({ ...p, username: e.target.value }))}
                                        required={!editingUser}
                                    />
                                </div>
                            )}
                            <div className="form-group">
                                <label>EMAIL</label>
                                <input
                                    type="email"
                                    value={formData.email}
                                    onChange={(e) => setFormData(p => ({ ...p, email: e.target.value }))}
                                    required={!editingUser}
                                />
                            </div>
                            <div className="form-group">
                                <label>{editingUser ? 'NEW PASSWORD (leave blank to keep)' : 'PASSWORD'}</label>
                                <input
                                    type="password"
                                    value={formData.password}
                                    onChange={(e) => setFormData(p => ({ ...p, password: e.target.value }))}
                                    required={!editingUser}
                                />
                            </div>
                            <div className="form-group">
                                <label>ROLE</label>
                                <select value={formData.role} onChange={(e) => setFormData(p => ({ ...p, role: e.target.value }))}>
                                    <option value="Admin">Admin — Full Access</option>
                                    <option value="Analyst">Analyst — View, Search, Reports</option>
                                    <option value="Viewer">Viewer — Read Only</option>
                                </select>
                            </div>
                            {editingUser && (
                                <div className="form-group">
                                    <label>STATUS</label>
                                    <select value={formData.status} onChange={(e) => setFormData(p => ({ ...p, status: e.target.value }))}>
                                        <option value="active">Active</option>
                                        <option value="disabled">Disabled</option>
                                    </select>
                                </div>
                            )}
                            {error && <div className="form-error">{error}</div>}
                            <button type="submit" className="submit-btn">
                                {editingUser ? 'UPDATE USER' : 'CREATE USER'}
                            </button>
                        </form>
                    </div>
                </div>
            )}

            {/* Delete Confirmation */}
            {deleteConfirm && (
                <div className="modal-overlay" onClick={() => setDeleteConfirm(null)}>
                    <div className="modal-card confirm-card" onClick={e => e.stopPropagation()}>
                        <div className="confirm-icon">⚠️</div>
                        <h3>DELETE USER</h3>
                        <p>Are you sure you want to delete <strong>{deleteConfirm.username}</strong>?</p>
                        <p className="confirm-warning">This action cannot be undone.</p>
                        <div className="confirm-actions">
                            <button className="cancel-btn" onClick={() => setDeleteConfirm(null)}>CANCEL</button>
                            <button className="danger-btn" onClick={() => handleDelete(deleteConfirm.id)}>DELETE</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default UserManagement;

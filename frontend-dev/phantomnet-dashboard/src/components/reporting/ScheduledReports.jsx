import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
    Plus,
    Trash2,
    Bell,
    Mail,
    Clock,
    AlertCircle,
    CheckCircle,
    Edit2
} from 'lucide-react';
import './ScheduledReports.css';

const API_BASE = 'http://localhost:8000/api/v1/reports';

const ScheduledReports = () => {
    const [schedules, setSchedules] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showAdd, setShowAdd] = useState(false);
    const [editId, setEditId] = useState(null);
    const [formData, setFormData] = useState({
        name: '',
        template_type: 'Executive Summary',
        frequency: 'Daily',
        schedule_time: '09:00',
        day_of_week: 'mon',
        recipients: ''
    });

    const fetchSchedules = async () => {
        setLoading(true);
        try {
            const response = await axios.get(`${API_BASE}/schedules`);
            setSchedules(response.data);
        } catch (err) {
            console.error('Error fetching schedules:', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchSchedules();
    }, []);

    const resetForm = () => {
        setShowAdd(false);
        setEditId(null);
        setFormData({
            name: '',
            template_type: 'Executive Summary',
            frequency: 'Daily',
            schedule_time: '09:00',
            day_of_week: 'mon',
            recipients: ''
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            if (editId) {
                await axios.put(`${API_BASE}/schedule/${editId}`, formData);
            } else {
                await axios.post(`${API_BASE}/schedule`, formData);
            }
            resetForm();
            fetchSchedules();
        } catch (err) {
            console.error('Error saving schedule:', err);
            alert('Failed to save schedule. Backend might be offline.');
        }
    };

    const handleEdit = (s) => {
        setFormData({
            name: s.name,
            template_type: s.template_type,
            frequency: s.frequency,
            schedule_time: s.schedule_time,
            day_of_week: s.day_of_week || 'mon',
            recipients: s.recipients
        });
        setEditId(s.id);
        setShowAdd(true);
    };

    const handleDelete = async (id) => {
        if (!window.confirm('Are you sure you want to delete this schedule?')) return;
        try {
            await axios.delete(`${API_BASE}/schedule/${id}`);
            fetchSchedules();
        } catch (err) {
            console.error('Error deleting schedule:', err);
        }
    };

    return (
        <div className="scheduled-reports">
            <div className="sched-header">
                <div className="title-group">
                    <h3><Bell className="w-5 h-5 text-cyan-400" /> Scheduled Deliveries</h3>
                    <p>Automated intelligence feeds delivered to your inbox.</p>
                </div>
                <button onClick={() => showAdd ? resetForm() : setShowAdd(true)} className={`btn-add ${showAdd ? 'active' : ''}`}>
                    {showAdd ? 'Cancel' : <><Plus className="w-4 h-4" /> New Schedule</>}
                </button>
            </div>

            {showAdd && (
                <form className="add-schedule-form" onSubmit={handleSubmit}>
                    <div className="form-header-small">
                        {editId ? 'Modify Automation' : 'New Delivery Automation'}
                    </div>
                    <div className="form-grid">
                        <div className="form-group">
                            <label>Report Name</label>
                            <input
                                type="text"
                                required
                                value={formData.name}
                                onChange={e => setFormData({ ...formData, name: e.target.value })}
                                placeholder="e.g. Weekly CISO Brief"
                            />
                        </div>
                        <div className="form-group">
                            <label>Template</label>
                            <select
                                value={formData.template_type}
                                onChange={e => setFormData({ ...formData, template_type: e.target.value })}
                            >
                                <option>Executive Summary</option>
                                <option>Technical Detail</option>
                                <option>Compliance Report</option>
                                <option>Threat Intelligence Brief</option>
                            </select>
                        </div>
                        <div className="form-group">
                            <label>Frequency</label>
                            <select
                                value={formData.frequency}
                                onChange={e => setFormData({ ...formData, frequency: e.target.value })}
                            >
                                <option>Daily</option>
                                <option>Weekly</option>
                                <option>Monthly</option>
                            </select>
                        </div>
                        {formData.frequency === 'Weekly' && (
                            <div className="form-group">
                                <label>Day of Week</label>
                                <select
                                    value={formData.day_of_week}
                                    onChange={e => setFormData({ ...formData, day_of_week: e.target.value })}
                                >
                                    <option value="mon">Monday</option>
                                    <option value="tue">Tuesday</option>
                                    <option value="wed">Wednesday</option>
                                    <option value="thu">Thursday</option>
                                    <option value="fri">Friday</option>
                                    <option value="sat">Saturday</option>
                                    <option value="sun">Sunday</option>
                                </select>
                            </div>
                        )}
                        <div className="form-group">
                            <label>Time (24h)</label>
                            <input
                                type="time"
                                required
                                value={formData.schedule_time}
                                onChange={e => setFormData({ ...formData, schedule_time: e.target.value })}
                            />
                        </div>
                        <div className="form-group full-width">
                            <label>Recipients (Comma separated)</label>
                            <input
                                type="text"
                                required
                                value={formData.recipients}
                                onChange={e => setFormData({ ...formData, recipients: e.target.value })}
                                placeholder="admin@phantomnet.ai, security-team@corp.com"
                            />
                        </div>
                    </div>
                    <div className="form-actions">
                        <button type="submit" className="btn-submit">
                            {editId ? 'Update Automation' : 'Create Automation'}
                        </button>
                    </div>
                </form>
            )}

            <div className="schedules-list">
                {loading ? (
                    <div className="list-loading">Scanning automation table...</div>
                ) : schedules.length > 0 ? (
                    <div className="schedules-table">
                        <div className="table-header">
                            <span>Report Name</span>
                            <span>Frequency</span>
                            <span>Next Run</span>
                            <span>Recipients</span>
                            <span>Status</span>
                            <span>Actions</span>
                        </div>
                        {schedules.map(s => (
                            <div key={s.id} className="table-row">
                                <div className="row-name">
                                    <strong>{s.name}</strong>
                                    <span className="template-tag">{s.template_type}</span>
                                </div>
                                <div className="row-freq">
                                    <Clock className="w-3 h-3" /> {s.frequency}
                                    {s.frequency === 'Weekly' && ` (${s.day_of_week})`} @ {s.schedule_time}
                                </div>
                                <div className="row-next">
                                    {s.next_run ? new Date(s.next_run).toLocaleString() : 'Pending'}
                                </div>
                                <div className="row-recipients">
                                    <Mail className="w-3 h-3" /> {s.recipients.split(',')[0]} {s.recipients.split(',').length > 1 && `+${s.recipients.split(',').length - 1}`}
                                </div>
                                <div className="row-status">
                                    {s.is_active ?
                                        <span className="status-active"><CheckCircle className="w-3 h-3" /> Active</span> :
                                        <span className="status-paused">Paused</span>
                                    }
                                </div>
                                <div className="row-actions">
                                    <button onClick={() => handleEdit(s)} className="btn-edit mr-2">
                                        <Edit2 className="w-4 h-4" />
                                    </button>
                                    <button onClick={() => handleDelete(s.id)} className="btn-delete">
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <div className="list-empty">
                        <AlertCircle className="w-8 h-8 mb-2 opacity-20" />
                        <p>No active report schedules found.</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ScheduledReports;

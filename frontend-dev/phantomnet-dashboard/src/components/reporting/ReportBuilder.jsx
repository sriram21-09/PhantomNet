import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
    Download,
    RefreshCw,
    Calendar,
    Filter,
    FileJson,
    FileSpreadsheet,
    FileText as FilePdf,
    CheckCircle2,
    Clock
} from 'lucide-react';
import ReportTemplates from './ReportTemplates';
import { exportToPDF } from '../../utils/exportPDF';
import { exportToExcel } from '../../utils/exportExcel';
import { exportToCSV, exportToJSON } from '../../utils/exportUtils';
import './ReportBuilder.css';

const API_BASE = 'http://localhost:8000/api/v1/reports';

const ALL_SECTIONS = [
    "Executive Summary",
    "Attack Timeline",
    "Geographic Distribution",
    "Top Attackers",
    "Attack Patterns",
    "Event Logs",
    "Recommendations"
];

const ReportBuilder = () => {
    const [selectedTemplate, setSelectedTemplate] = useState(null);
    const [dateRange, setDateRange] = useState('24h');
    const [honeypotFilter, setHoneypotFilter] = useState('ALL');
    const [threatLevelFilter, setThreatLevelFilter] = useState('ALL');
    const [protocolFilter, setProtocolFilter] = useState('ALL');
    const [includeSections, setIncludeSections] = useState(ALL_SECTIONS);
    const [reportTitle, setReportTitle] = useState('');
    const [loading, setLoading] = useState(false);
    const [previewData, setPreviewData] = useState(null);
    const [error, setError] = useState(null);

    const [reportDescription, setReportDescription] = useState('Cybersecurity intelligence report for PhantomNet active defense nodes.');

    const fetchPreview = async () => {
        if (!selectedTemplate) return;
        setLoading(true);
        setError(null);
        try {
            const response = await axios.get(`${API_BASE}/generate`, {
                params: {
                    template_type: selectedTemplate.title,
                    date_range: dateRange,
                    honeypot: honeypotFilter,
                    threat_level: threatLevelFilter,
                    protocol: protocolFilter,
                    include_sections: includeSections.join(',')
                }
            });
            setPreviewData({
                ...response.data,
                description: reportDescription
            });
        } catch (err) {
            console.error('Error fetching report preview:', err);
            setError('Failed to generate preview. Ensure backend is running.');
            setPreviewData({
                title: selectedTemplate.title,
                generated_at: new Date().toISOString(),
                description: reportDescription,
                sections: {
                    overview: { total_threats: 42, severity: "High" },
                    recent_activity: [{ time: "10:00", event: "Login Attempt" }]
                }
            });
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (selectedTemplate) {
            fetchPreview();
            setReportTitle(`${selectedTemplate.title} Report - ${new Date().toLocaleDateString()}`);
        }
    }, [selectedTemplate, dateRange, honeypotFilter, threatLevelFilter, protocolFilter, includeSections, reportDescription]);

    const handleExport = (format) => {
        if (!previewData) return;
        const finalData = {
            ...previewData,
            title: reportTitle,
            description: reportDescription
        };
        switch (format) {
            case 'pdf': exportToPDF(finalData, reportTitle); break;
            case 'excel': exportToExcel(finalData, reportTitle); break;
            case 'csv': exportToCSV(finalData, reportTitle); break;
            case 'json': exportToJSON(finalData, reportTitle); break;
            default: break;
        }
    };

    const toggleSection = (section) => {
        setIncludeSections(prev =>
            prev.includes(section)
                ? prev.filter(s => s !== section)
                : [...prev, section]
        );
    };

    return (
        <div className="report-builder">
            <div className="builder-header">
                <h2>Custom Report Builder</h2>
                <p>Design and export intelligence reports based on simulated attack data.</p>
            </div>

            <div className="builder-content">
                <aside className="builder-controls">
                    <div className="control-group">
                        <label><Calendar className="w-4 h-4" /> Date Range</label>
                        <select value={dateRange} onChange={(e) => setDateRange(e.target.value)}>
                            <option value="24h">Last 24 Hours</option>
                            <option value="7d">Last 7 Days</option>
                            <option value="30d">Last 30 Days</option>
                        </select>
                    </div>

                    <div className="control-group">
                        <label><Filter className="w-4 h-4" /> Honeypot Filter</label>
                        <select value={honeypotFilter} onChange={(e) => setHoneypotFilter(e.target.value)}>
                            <option value="ALL">All Honeypots</option>
                            <option value="SSH">SSH Honeypot</option>
                            <option value="HTTP">Web Honeypot</option>
                            <option value="FTP">FTP Honeypot</option>
                            <option value="SMTP">SMTP Honeypot</option>
                        </select>
                    </div>

                    <div className="control-group">
                        <label><Filter className="w-4 h-4" /> Threat Level</label>
                        <select value={threatLevelFilter} onChange={(e) => setThreatLevelFilter(e.target.value)}>
                            <option value="ALL">All Levels</option>
                            <option value="LOW">Low</option>
                            <option value="MEDIUM">Medium</option>
                            <option value="HIGH">High</option>
                            <option value="CRITICAL">Critical</option>
                        </select>
                    </div>

                    <div className="control-group">
                        <label><Filter className="w-4 h-4" /> Sections to Include</label>
                        <div className="sections-checklist">
                            {ALL_SECTIONS.map(section => (
                                <label key={section} className="checkbox-label">
                                    <input
                                        type="checkbox"
                                        checked={includeSections.includes(section)}
                                        onChange={() => toggleSection(section)}
                                    />
                                    {section}
                                </label>
                            ))}
                        </div>
                    </div>

                    <div className="control-group">
                        <label><Filter className="w-4 h-4" /> Report Title</label>
                        <input
                            type="text"
                            value={reportTitle}
                            onChange={(e) => setReportTitle(e.target.value)}
                            placeholder="Enter report title..."
                        />
                    </div>

                    <div className="control-group">
                        <label><Filter className="w-4 h-4" /> Report Description</label>
                        <textarea
                            value={reportDescription}
                            onChange={(e) => setReportDescription(e.target.value)}
                            placeholder="Briefly describe report contents..."
                            className="builder-textarea"
                            rows={3}
                        />
                    </div>

                    <div className="export-actions">
                        <h4>Export Formats</h4>
                        <div className="export-buttons">
                            <button onClick={() => handleExport('pdf')} disabled={!previewData} className="btn-export pdf">
                                <FilePdf className="w-4 h-4" /> PDF
                            </button>
                            <button onClick={() => handleExport('excel')} disabled={!previewData} className="btn-export excel">
                                <FileSpreadsheet className="w-4 h-4" /> Excel
                            </button>
                            <button onClick={() => handleExport('csv')} disabled={!previewData} className="btn-export csv">
                                <Download className="w-4 h-4" /> CSV
                            </button>
                            <button onClick={() => handleExport('json')} disabled={!previewData} className="btn-export json">
                                <FileJson className="w-4 h-4" /> JSON
                            </button>
                        </div>
                    </div>
                </aside>

                <main className="builder-main">
                    <ReportTemplates
                        onSelect={setSelectedTemplate}
                        selectedId={selectedTemplate?.id}
                    />

                    <div className="preview-container">
                        <div className="preview-header">
                            <h3>Live Preview</h3>
                            <button onClick={fetchPreview} className="btn-refresh" disabled={loading}>
                                <RefreshCw className={`w-4 h-4 ${loading ? 'spin' : ''}`} />
                            </button>
                        </div>

                        {loading ? (
                            <div className="preview-loading">
                                <div className="loader"></div>
                                <p>Aggregating defense data...</p>
                            </div>
                        ) : previewData ? (
                            <div className="preview-sheet">
                                <div className="sheet-header">
                                    <div className="sheet-title">{reportTitle}</div>
                                    <div className="sheet-meta">Generated: {previewData.generated_at}</div>
                                </div>
                                <div className="sheet-body">
                                    {Object.entries(previewData.sections).map(([name, content]) => (
                                        <div key={name} className="preview-section">
                                            <h5>{name.replace(/_/g, ' ').toUpperCase()}</h5>
                                            <pre>{JSON.stringify(content, null, 2)}</pre>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ) : (
                            <div className="preview-empty">
                                <Clock className="w-12 h-12 mb-4" />
                                <p>Select a template to generate a preview</p>
                            </div>
                        )}
                        {error && <div className="preview-error">{error}</div>}
                    </div>
                </main>
            </div>
        </div>
    );
};

export default ReportBuilder;

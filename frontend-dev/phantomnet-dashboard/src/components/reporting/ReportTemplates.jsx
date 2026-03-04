import React from 'react';
import {
    BarChart,
    FileText,
    ShieldAlert,
    Zap,
    ChevronRight
} from 'lucide-react';
import './ReportTemplates.css';

const TEMPLATES = [
    {
        id: 'executive',
        title: 'Executive Summary',
        description: 'High-level overview of system security posture, main threats, and safety score.',
        icon: <BarChart className="w-6 h-6" />,
        color: '#00d2ff'
    },
    {
        id: 'technical',
        title: 'Technical Detail',
        description: 'In-depth analysis of protocols, recent logs, and specific attack vectors.',
        icon: <FileText className="w-6 h-6" />,
        color: '#9d50bb'
    },
    {
        id: 'compliance',
        title: 'Compliance Report',
        description: 'Adherence to security policies and status of defense mechanisms.',
        icon: <ShieldAlert className="w-6 h-6" />,
        color: '#ff4b2b'
    },
    {
        id: 'threat_intel',
        title: 'Threat Intel Brief',
        description: 'Intelligence on attacker geolocation and emerging patterns.',
        icon: <Zap className="w-6 h-6" />,
        color: '#f9d423'
    }
];

const ReportTemplates = ({ onSelect, selectedId }) => {
    return (
        <div className="report-templates">
            <h3 className="section-title">Select Report Template</h3>
            <div className="templates-grid">
                {TEMPLATES.map((template) => (
                    <div
                        key={template.id}
                        className={`template-card ${selectedId === template.id ? 'active' : ''}`}
                        onClick={() => onSelect(template)}
                        style={{ '--accent-color': template.color }}
                    >
                        <div className="template-icon" style={{ backgroundColor: `${template.color}22`, color: template.color }}>
                            {template.icon}
                        </div>
                        <div className="template-info">
                            <h4>{template.title}</h4>
                            <p>{template.description}</p>
                        </div>
                        <div className="template-select">
                            <ChevronRight className="w-5 h-5" />
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default ReportTemplates;

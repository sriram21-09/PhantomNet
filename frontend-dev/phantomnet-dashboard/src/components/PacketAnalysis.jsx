import React, { useState, useEffect } from "react";
import {
    PieChart,
    Pie,
    Cell,
    Tooltip,
    ResponsiveContainer,
    BarChart,
    Bar,
    XAxis,
    YAxis,
    CartesianGrid,
} from "recharts";
import {
    FaDatabase,
    FaDownload,
    FaShieldAlt,
    FaNetworkWired,
    FaExclamationTriangle,
    FaServer,
    FaHdd,
    FaClock,
    FaSkullCrossbones,
    FaBug,
    FaSearch,
} from "react-icons/fa";
import "../Styles/components/PacketAnalysis.css";

const PROTOCOL_COLORS = ["#3b82f6", "#06b6d4", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6"];

const PacketAnalysis = () => {
    const [stats, setStats] = useState(null);
    const [analysis, setAnalysis] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [statsRes, analysisRes] = await Promise.all([
                    fetch("/api/v1/pcap/stats"),
                    fetch("/api/v1/pcap/analysis/0"), // Default/mock analysis
                ]);
                const statsData = await statsRes.json();
                const analysisData = await analysisRes.json();
                setStats(statsData);
                setAnalysis(analysisData?.report?.details || null);
            } catch (err) {
                console.error("Failed to fetch PCAP data:", err);
                // Use mock data for development when backend is unavailable
                setStats({
                    total_captures: 42,
                    total_size_mb: 128.5,
                    active_captures: 1,
                    retention_days: 30,
                });
                setAnalysis({
                    total_packets: 1247,
                    total_bytes: 892340,
                    duration_seconds: 60,
                    protocol_distribution: [
                        { protocol: "TCP", count: 680, percentage: 54.5 },
                        { protocol: "UDP", count: 312, percentage: 25.0 },
                        { protocol: "HTTP", count: 142, percentage: 11.4 },
                        { protocol: "DNS", count: 78, percentage: 6.3 },
                        { protocol: "ICMP", count: 23, percentage: 1.8 },
                        { protocol: "SSH", count: 12, percentage: 1.0 },
                    ],
                    top_talkers: [
                        { ip: "192.168.1.105", packets: 234, direction: "source" },
                        { ip: "10.0.0.45", packets: 187, direction: "source" },
                        { ip: "172.16.0.12", packets: 156, direction: "source" },
                        { ip: "192.168.1.200", packets: 98, direction: "source" },
                        { ip: "10.0.0.100", packets: 67, direction: "source" },
                    ],
                    malicious_patterns: [
                        {
                            type: "PORT_SCAN",
                            severity: "HIGH",
                            source_ip: "10.0.0.45",
                            ports_scanned: 47,
                            detail: "10.0.0.45 probed 47 unique ports",
                        },
                        {
                            type: "C2_BEACONING",
                            severity: "CRITICAL",
                            source_ip: "172.16.0.12",
                            avg_interval_sec: 30.0,
                            detail: "Periodic connections every ~30.0s from 172.16.0.12",
                        },
                    ],
                    suspicious_packets: [
                        {
                            index: 42,
                            type: "NULL_SCAN",
                            severity: "HIGH",
                            src_ip: "10.0.0.45",
                            dst_ip: "192.168.1.1",
                            detail: "NULL scan packet → 192.168.1.1:445",
                        },
                        {
                            index: 789,
                            type: "BUFFER_OVERFLOW_ATTEMPT",
                            severity: "CRITICAL",
                            src_ip: "172.16.0.12",
                            dst_ip: "192.168.1.105",
                            detail: "Oversized payload (4096 bytes) — possible buffer overflow",
                        },
                    ],
                    iocs: {
                        ips: ["10.0.0.45", "172.16.0.12"],
                        domains: ["evil.example.com", "c2-server.net"],
                        urls: ["/admin/shell.php", "/cgi-bin/exploit"],
                    },
                });
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, []);

    const handleDownload = async (eventId) => {
        try {
            const response = await fetch(`/api/v1/events/${eventId}/pcap`);
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `phantomnet_event_${eventId}.pcap`;
                a.click();
                window.URL.revokeObjectURL(url);
            }
        } catch (err) {
            console.error("Download failed:", err);
        }
    };

    if (loading) {
        return (
            <div className="packet-analysis-page">
                <div className="pcap-loading">
                    <div className="pcap-spinner" />
                </div>
            </div>
        );
    }

    const patternIcons = {
        PORT_SCAN: <FaSearch />,
        SYN_FLOOD: <FaSkullCrossbones />,
        NULL_SCAN: <FaBug />,
        C2_BEACONING: <FaNetworkWired />,
        DATA_EXFILTRATION: <FaHdd />,
        BUFFER_OVERFLOW_ATTEMPT: <FaExclamationTriangle />,
    };

    return (
        <div className="packet-analysis-page">
            {/* ---- Header ---- */}
            <div className="pcap-header">
                <div>
                    <h1>
                        <FaDatabase className="header-icon" /> PCAP Analysis
                    </h1>
                    <p className="pcap-subtitle">
                        Deep packet inspection &amp; automated malicious pattern detection
                    </p>
                </div>
                <div className="pcap-download-section">
                    <button className="pcap-download-btn" onClick={() => handleDownload(0)} id="pcap-download-btn">
                        <FaDownload className="btn-icon" />
                        Download PCAP
                    </button>
                </div>
            </div>

            {/* ---- Stats Cards ---- */}
            <div className="pcap-stats-row">
                <div className="pcap-stat-card accent-blue">
                    <div className="stat-icon"><FaDatabase /></div>
                    <div className="stat-value">{stats?.total_captures ?? 0}</div>
                    <div className="stat-label">Total Captures</div>
                </div>
                <div className="pcap-stat-card accent-cyan">
                    <div className="stat-icon"><FaHdd /></div>
                    <div className="stat-value">{stats?.total_size_mb ?? 0} MB</div>
                    <div className="stat-label">Disk Usage</div>
                </div>
                <div className="pcap-stat-card accent-green">
                    <div className="stat-icon"><FaServer /></div>
                    <div className="stat-value">{stats?.active_captures ?? 0}</div>
                    <div className="stat-label">Active Captures</div>
                </div>
                <div className="pcap-stat-card accent-amber">
                    <div className="stat-icon"><FaNetworkWired /></div>
                    <div className="stat-value">{analysis?.total_packets?.toLocaleString() ?? 0}</div>
                    <div className="stat-label">Packets Analyzed</div>
                </div>
                <div className="pcap-stat-card accent-red">
                    <div className="stat-icon"><FaExclamationTriangle /></div>
                    <div className="stat-value">{analysis?.malicious_patterns?.length ?? 0}</div>
                    <div className="stat-label">Threats Detected</div>
                </div>
            </div>

            {/* ---- Main Content ---- */}
            <div className="pcap-main-grid">
                {/* Protocol Distribution */}
                <div className="pcap-panel" id="protocol-distribution-panel">
                    <h3 className="panel-title">
                        <FaShieldAlt className="title-icon" /> Protocol Distribution
                    </h3>
                    {analysis?.protocol_distribution?.length > 0 ? (
                        <div className="protocol-chart-wrapper">
                            <ResponsiveContainer>
                                <PieChart>
                                    <Pie
                                        data={analysis.protocol_distribution}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={90}
                                        paddingAngle={4}
                                        dataKey="count"
                                        nameKey="protocol"
                                        stroke="none"
                                        animationBegin={0}
                                        animationDuration={800}
                                    >
                                        {analysis.protocol_distribution.map((entry, idx) => (
                                            <Cell
                                                key={`cell-${idx}`}
                                                fill={PROTOCOL_COLORS[idx % PROTOCOL_COLORS.length]}
                                                style={{
                                                    filter: `drop-shadow(0 0 6px ${PROTOCOL_COLORS[idx % PROTOCOL_COLORS.length]}44)`,
                                                }}
                                            />
                                        ))}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{
                                            background: "rgba(15, 23, 42, 0.95)",
                                            border: "1px solid rgba(59, 130, 246, 0.2)",
                                            borderRadius: "8px",
                                            color: "#e2e8f0",
                                            fontSize: "0.82rem",
                                        }}
                                        formatter={(value, name) => [`${value} packets`, name]}
                                    />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                    ) : (
                        <div className="empty-state">
                            <FaDatabase className="empty-icon" />
                            <p>No protocol data available</p>
                        </div>
                    )}
                </div>

                {/* Top Talkers */}
                <div className="pcap-panel" id="top-talkers-panel">
                    <h3 className="panel-title">
                        <FaNetworkWired className="title-icon" /> Top Talkers
                    </h3>
                    {analysis?.top_talkers?.length > 0 ? (
                        <table className="top-talkers-table">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>Source IP</th>
                                    <th>Packets</th>
                                    <th>Direction</th>
                                </tr>
                            </thead>
                            <tbody>
                                {analysis.top_talkers.map((talker, idx) => (
                                    <tr key={idx}>
                                        <td>
                                            <span className={`rank-badge ${idx < 3 ? "top-3" : ""}`}>{idx + 1}</span>
                                        </td>
                                        <td className="ip-cell">{talker.ip}</td>
                                        <td className="packet-count-cell">{talker.packets.toLocaleString()}</td>
                                        <td style={{ color: "#94a3b8", fontSize: "0.78rem" }}>{talker.direction}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    ) : (
                        <div className="empty-state">
                            <FaNetworkWired className="empty-icon" />
                            <p>No top talker data</p>
                        </div>
                    )}
                </div>

                {/* Malicious Patterns */}
                <div className="pcap-panel" id="malicious-patterns-panel">
                    <h3 className="panel-title">
                        <FaSkullCrossbones className="title-icon" /> Malicious Patterns
                    </h3>
                    {analysis?.malicious_patterns?.length > 0 ? (
                        <div className="pattern-list">
                            {analysis.malicious_patterns.map((pattern, idx) => (
                                <div className="pattern-card" key={idx}>
                                    <div className="pattern-header">
                                        <span className="pattern-type">
                                            {patternIcons[pattern.type] || <FaExclamationTriangle />}
                                            {pattern.type.replace(/_/g, " ")}
                                        </span>
                                        <span className={`severity-badge ${pattern.severity}`}>{pattern.severity}</span>
                                    </div>
                                    <div className="pattern-detail">
                                        {pattern.detail}{" "}
                                        {pattern.source_ip && (
                                            <span className="pattern-ip">({pattern.source_ip})</span>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="empty-state">
                            <FaShieldAlt className="empty-icon" />
                            <p>No malicious patterns detected</p>
                        </div>
                    )}
                </div>

                {/* IOCs */}
                <div className="pcap-panel" id="iocs-panel">
                    <h3 className="panel-title">
                        <FaBug className="title-icon" /> Indicators of Compromise
                    </h3>
                    {analysis?.iocs && Object.values(analysis.iocs).some((arr) => arr.length > 0) ? (
                        <div className="ioc-grid">
                            {Object.entries(analysis.iocs).map(([category, items]) => (
                                <div className="ioc-category" key={category}>
                                    <div className="ioc-category-label">
                                        {category.toUpperCase()} ({items.length})
                                    </div>
                                    <div className="ioc-list">
                                        {items.slice(0, 8).map((item, idx) => (
                                            <div className="ioc-item" key={idx}>{item}</div>
                                        ))}
                                        {items.length > 8 && (
                                            <div className="ioc-item" style={{ color: "#64748b" }}>
                                                +{items.length - 8} more
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="empty-state">
                            <FaBug className="empty-icon" />
                            <p>No IOCs extracted</p>
                        </div>
                    )}
                </div>

                {/* Suspicious Packets — full width */}
                <div className="pcap-panel full-width" id="suspicious-packets-panel">
                    <h3 className="panel-title">
                        <FaExclamationTriangle className="title-icon" /> Suspicious Packets
                    </h3>
                    {analysis?.suspicious_packets?.length > 0 ? (
                        <div className="suspicious-list">
                            {analysis.suspicious_packets.map((pkt, idx) => (
                                <div className="suspicious-item" key={idx}>
                                    <span className={`severity-badge ${pkt.severity}`}>{pkt.severity}</span>
                                    <div className="suspicious-detail">
                                        <span className="suspicious-type">{pkt.type.replace(/_/g, " ")}</span>
                                        {pkt.detail}
                                        <div className="suspicious-ips">
                                            {pkt.src_ip} → {pkt.dst_ip}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="empty-state">
                            <FaExclamationTriangle className="empty-icon" />
                            <p>No suspicious packets found</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default PacketAnalysis;

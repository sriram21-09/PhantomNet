import React, { useState, useEffect, useCallback, useMemo } from "react";
import { useLocation } from "react-router-dom";
import {
    PieChart,
    Pie,
    Cell,
    Tooltip,
    ResponsiveContainer,
} from "recharts";
import {
    FaDatabase,
    FaDownload,
    FaShieldAlt,
    FaNetworkWired,
    FaExclamationTriangle,
    FaServer,
    FaHdd,
    FaSkullCrossbones,
    FaBug,
    FaSearch,
    FaSync,
    FaFileAlt,
    FaCheckCircle,
    FaTimesCircle,
    FaClock,
} from "react-icons/fa";
import { useRealTime } from "../context/RealTimeContext";
import "../Styles/components/PacketAnalysis.css";

const PROTOCOL_COLORS = ["#3b82f6", "#06b6d4", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899", "#6366f1"];

const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};

const formatDate = (isoString) => {
    if (!isoString) return "Unknown";
    try {
        const d = new Date(isoString);
        return isNaN(d.getTime()) ? isoString : d.toLocaleString();
    } catch {
        return isoString;
    }
};

const PacketAnalysis = () => {
    const location = useLocation();
    const queryParams = useMemo(() => new URLSearchParams(location.search), [location.search]);
    const requestedId = queryParams.get("captureId") || queryParams.get("id");

    // Real-Time Context Integration (Existing WebSocket stream)
    const realTime = useRealTime();
    const latestPcapEvent = realTime?.latestPcapEvent;
    const isWsConnected = realTime?.isConnected;

    // Component State
    const [captures, setCaptures] = useState([]);
    const [totalCapturesCount, setTotalCapturesCount] = useState(0);
    const [selectedCaptureId, setSelectedCaptureId] = useState(null);
    const [stats, setStats] = useState(null);
    const [analysis, setAnalysis] = useState(null);

    // Loading & Error States
    const [loadingCaptures, setLoadingCaptures] = useState(true);
    const [loadingAnalysis, setLoadingAnalysis] = useState(false);
    const [capturesError, setCapturesError] = useState(null);
    const [analysisError, setAnalysisError] = useState(null);
    const [downloading, setDownloading] = useState(false);
    const [downloadError, setDownloadError] = useState(null);

    // Filter / Search State
    const [searchQuery, setSearchQuery] = useState("");

    // Currently selected capture metadata
    const selectedCapture = useMemo(() => {
        if (!selectedCaptureId || !captures.length) return null;
        return captures.find((c) => c.id === selectedCaptureId) || null;
    }, [selectedCaptureId, captures]);

    // Fetch Global Stats
    const fetchStats = useCallback(async () => {
        try {
            const res = await fetch("/api/v1/pcap/stats", {
                credentials: "include",
            });
            if (res.ok) {
                const data = await res.json();
                setStats(data);
            }
        } catch {
            // Stats fetch failure handled gracefully without wiping existing stats
        }
    }, []);

    // Fetch PCAP Analysis by ID with automatic retry for transient gateway restarts
    const loadAnalysis = useCallback(async (captureId, retryCount = 0) => {
        if (!captureId || captureId < 1) {
            setAnalysis(null);
            setAnalysisError("Invalid capture ID specified.");
            return;
        }

        setLoadingAnalysis(true);
        setAnalysisError(null);

        try {
            const res = await fetch(`/api/v1/pcap/analysis/${captureId}`, {
                credentials: "include",
            });

            if (!res.ok) {
                // If 502 Bad Gateway or 503/504 (upstream rebooting), auto-retry twice
                if ((res.status === 502 || res.status === 503 || res.status === 504) && retryCount < 2) {
                    setTimeout(() => {
                        fetchStats();
                        loadAnalysis(captureId, retryCount + 1);
                    }, 1200);
                    return;
                }

                let errorMsg = `Analysis failed with HTTP ${res.status}`;
                try {
                    const errorData = await res.json();
                    if (errorData.detail) {
                        errorMsg = typeof errorData.detail === "string" 
                            ? errorData.detail 
                            : JSON.stringify(errorData.detail);
                    }
                } catch {
                    // Fallback to HTTP status text
                    errorMsg = res.statusText || errorMsg;
                }

                if (res.status === 404) {
                    errorMsg = `Capture #${captureId} not found or PCAP file is missing on storage.`;
                } else if (res.status === 403) {
                    errorMsg = "Access denied: Analyst or Admin role required to inspect packet analysis.";
                } else if (res.status === 422) {
                    errorMsg = "Unprocessable Entity: Capture ID must be an integer >= 1.";
                }

                throw new Error(errorMsg);
            }

            const data = await res.json();
            const details = data?.report?.details || null;
            setAnalysis(details);
            fetchStats();
        } catch (err) {
            setAnalysis(null);
            setAnalysisError(err.message || "Failed to load PCAP analysis report.");
        } finally {
            setLoadingAnalysis(false);
        }
    }, [fetchStats]);

    // Fetch Captures List
    const fetchCaptures = useCallback(async (preferredId = null) => {
        setCapturesError(null);
        try {
            const res = await fetch("/api/v1/pcap/captures?limit=100&offset=0", {
                credentials: "include",
            });

            if (!res.ok) {
                let msg = `Failed to load captures: HTTP ${res.status}`;
                if (res.status === 401 || res.status === 403) {
                    msg = "Permission denied: Analyst or Admin authentication required.";
                }
                throw new Error(msg);
            }

            const data = await res.json();
            const list = Array.isArray(data?.captures) ? data.captures : [];
            setCaptures(list);
            setTotalCapturesCount(data?.total ?? list.length);

            // Determine which capture to select
            setSelectedCaptureId((prevSelected) => {
                const targetId = preferredId ? Number(preferredId) : prevSelected;

                if (targetId && list.some((c) => c.id === targetId)) {
                    return targetId;
                }
                // If requestedId from URL query param exists and matches
                if (requestedId) {
                    const matchFromQuery = list.find((c) => c.id === Number(requestedId));
                    if (matchFromQuery) return matchFromQuery.id;
                }
                // Default to newest capture if available
                return list.length > 0 ? list[0].id : null;
            });
        } catch (err) {
            setCaptures([]);
            setCapturesError(err.message || "Could not retrieve PCAP capture catalog from server.");
        } finally {
            setLoadingCaptures(false);
        }
    }, [requestedId]);

    // Initial Data Fetch
    useEffect(() => {
        fetchCaptures(requestedId);
        fetchStats();
    }, [fetchCaptures, fetchStats, requestedId]);

    // When selected capture changes, trigger analysis
    useEffect(() => {
        if (selectedCaptureId) {
            loadAnalysis(selectedCaptureId);
        } else {
            setAnalysis(null);
        }
    }, [selectedCaptureId, loadAnalysis]);

    // Instant refresh upon receiving real-time WebSocket PCAP event
    useEffect(() => {
        if (latestPcapEvent) {
            fetchCaptures(selectedCaptureId);
            fetchStats();
        }
    }, [latestPcapEvent, fetchCaptures, fetchStats, selectedCaptureId]);

    // Real-time polling fallback: background refresh every 12 seconds
    useEffect(() => {
        const interval = setInterval(() => {
            fetchStats();
            // Silent refresh of capture catalog
            fetch("/api/v1/pcap/captures?limit=100&offset=0", { credentials: "include" })
                .then((res) => (res.ok ? res.json() : null))
                .then((data) => {
                    if (data?.captures) {
                        setCaptures(data.captures);
                        setTotalCapturesCount(data.total ?? data.captures.length);
                        // Auto-select if currently nothing is selected
                        setSelectedCaptureId((curr) => {
                            if (!curr && data.captures.length > 0) {
                                return data.captures[0].id;
                            }
                            return curr;
                        });
                    }
                })
                .catch(() => {});
        }, 12000);

        return () => clearInterval(interval);
    }, [fetchStats]);

    // Download Handler
    const handleDownload = async () => {
        if (!selectedCaptureId) return;

        setDownloading(true);
        setDownloadError(null);

        try {
            // Primary download endpoint
            let response = await fetch(`/api/v1/pcap/${selectedCaptureId}/download`, {
                credentials: "include",
            });

            // If 404, fallback to /api/v1/events/{id}/pcap
            if (response.status === 404) {
                response = await fetch(`/api/v1/events/${selectedCaptureId}/pcap`, {
                    credentials: "include",
                });
            }

            if (!response.ok) {
                if (response.status === 404) {
                    throw new Error(`PCAP file for capture #${selectedCaptureId} does not exist on storage.`);
                } else if (response.status === 403) {
                    throw new Error("Access denied: Not authorized to download raw PCAP captures.");
                } else {
                    throw new Error(`Download failed with HTTP ${response.status}: ${response.statusText}`);
                }
            }

            const blob = await response.blob();
            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = downloadUrl;

            // Extract filename from header or fallback
            const disposition = response.headers.get("Content-Disposition");
            let filename = `phantomnet_capture_${selectedCaptureId}.pcap`;
            if (disposition && disposition.includes("filename=")) {
                const match = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
                if (match && match[1]) {
                    filename = match[1].replace(/['"]/g, "");
                }
            } else if (selectedCapture?.filename) {
                filename = selectedCapture.filename;
            }

            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(downloadUrl);
        } catch (err) {
            setDownloadError(err.message || "Failed to download PCAP file.");
        } finally {
            setDownloading(false);
        }
    };

    // Filtered captures list for selector dropdown
    const filteredCaptures = useMemo(() => {
        if (!searchQuery.trim()) return captures;
        const q = searchQuery.toLowerCase();
        return captures.filter((c) =>
            String(c.id).includes(q) ||
            (c.filename && c.filename.toLowerCase().includes(q)) ||
            (c.status && c.status.toLowerCase().includes(q))
        );
    }, [captures, searchQuery]);

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
                        Deep packet inspection &amp; automated malicious pattern detection engine
                    </p>
                </div>
                <div className="pcap-download-section">
                    <button
                        className="pcap-download-btn"
                        onClick={handleDownload}
                        disabled={!selectedCaptureId || downloading}
                        id="pcap-download-btn"
                        title={selectedCaptureId ? `Download capture #${selectedCaptureId}` : "Select a capture first"}
                    >
                        {downloading ? (
                            <div className="pcap-btn-spinner" />
                        ) : (
                            <FaDownload className="btn-icon" />
                        )}
                        <span>{downloading ? "Downloading..." : "Download PCAP"}</span>
                    </button>
                </div>
            </div>

            {/* ---- Capture Selector Bar ---- */}
            <div className="pcap-selector-card" id="pcap-capture-selector-panel">
                <div className="pcap-selector-header">
                    <div className="selector-title">
                        <FaFileAlt className="selector-icon" />
                        <span>PCAP Capture Selector</span>
                        <span className="captures-badge">{totalCapturesCount} available</span>
                        {isWsConnected && (
                            <span className="pcap-ws-live-badge" title="Live WebSocket stream active">
                                <span className="ws-dot" /> LIVE
                            </span>
                        )}
                    </div>
                    <div className="selector-actions">
                        <div className="selector-search-box">
                            <FaSearch className="search-icon" />
                            <input
                                id="pcap-search-input"
                                type="text"
                                placeholder="Search captures (ID, name)..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                            />
                        </div>
                        <button
                            className="pcap-refresh-btn"
                            onClick={() => {
                                fetchCaptures(selectedCaptureId);
                                fetchStats();
                                if (selectedCaptureId) loadAnalysis(selectedCaptureId);
                            }}
                            title="Refresh captures & analysis"
                            id="pcap-refresh-btn"
                        >
                            <FaSync />
                        </button>
                    </div>
                </div>

                <div className="pcap-selector-controls">
                    <div className="selector-dropdown-wrapper">
                        <label htmlFor="pcap-capture-select" className="dropdown-label">
                            Selected Capture:
                        </label>
                        <select
                            id="pcap-capture-select"
                            className="pcap-select-dropdown"
                            value={selectedCaptureId || ""}
                            onChange={(e) => {
                                const newId = Number(e.target.value);
                                setSelectedCaptureId(newId);
                            }}
                            disabled={loadingCaptures || captures.length === 0}
                        >
                            {captures.length === 0 ? (
                                <option value="">No PCAP captures found</option>
                            ) : (
                                filteredCaptures.map((c) => (
                                    <option key={c.id} value={c.id}>
                                        #{c.id} — {c.filename} ({formatBytes(c.size_bytes)}) — {formatDate(c.timestamp)} [{c.status}]
                                    </option>
                                ))
                            )}
                        </select>
                    </div>

                    {selectedCapture && (
                        <div className="pcap-metadata-chips">
                            <div className="meta-chip">
                                <span className="chip-key">ID:</span>
                                <span className="chip-val">#{selectedCapture.id}</span>
                            </div>
                            <div className="meta-chip">
                                <span className="chip-key">File:</span>
                                <span className="chip-val mono">{selectedCapture.filename}</span>
                            </div>
                            <div className="meta-chip">
                                <span className="chip-key">Size:</span>
                                <span className="chip-val">{formatBytes(selectedCapture.size_bytes)}</span>
                            </div>
                            <div className="meta-chip">
                                <span className="chip-key">Status:</span>
                                <span className={`chip-val status-${selectedCapture.status}`}>
                                    {["available", "complete"].includes(selectedCapture.status) ? (
                                        <FaCheckCircle className="status-icon success" />
                                    ) : (
                                        <FaTimesCircle className="status-icon" />
                                    )}
                                    {selectedCapture.status}
                                </span>
                            </div>
                            <div className="meta-chip">
                                <FaClock className="chip-icon" />
                                <span className="chip-val">{formatDate(selectedCapture.timestamp)}</span>
                            </div>
                        </div>
                    )}
                </div>

                {downloadError && (
                    <div className="pcap-error-banner inline" id="pcap-download-error">
                        <FaExclamationTriangle />
                        <span>{downloadError}</span>
                        <button onClick={() => setDownloadError(null)} className="dismiss-btn">Dismiss</button>
                    </div>
                )}
            </div>

            {/* ---- Captures Error Banner ---- */}
            {capturesError && (
                <div className="pcap-error-banner" id="pcap-captures-error">
                    <FaExclamationTriangle />
                    <span>{capturesError}</span>
                    <button onClick={() => fetchCaptures(selectedCaptureId)} className="retry-btn">
                        Retry Loading Captures
                    </button>
                </div>
            )}

            {/* ---- Global & Selected Capture Stats Cards ---- */}
            <div className="pcap-stats-row">
                <div className="pcap-stat-card accent-blue">
                    <div className="stat-icon"><FaDatabase /></div>
                    <div className="stat-value">{stats?.total_captures ?? totalCapturesCount}</div>
                    <div className="stat-label">Total Captures</div>
                </div>
                <div className="pcap-stat-card accent-cyan">
                    <div className="stat-icon"><FaHdd /></div>
                    <div className="stat-value">{stats?.total_size_mb ?? 0} MB</div>
                    <div className="stat-label">Total Disk Usage</div>
                </div>
                <div className="pcap-stat-card accent-green">
                    <div className="stat-icon"><FaServer /></div>
                    <div className="stat-value">{stats?.active_captures ?? 0}</div>
                    <div className="stat-label">Active Captures</div>
                </div>
                <div className="pcap-stat-card accent-amber">
                    <div className="stat-icon"><FaNetworkWired /></div>
                    <div className="stat-value">
                        {loadingAnalysis ? "..." : (analysis ? (analysis?.total_packets?.toLocaleString() ?? "0") : "—")}
                    </div>
                    <div className="stat-label">Packets in Selected Capture</div>
                </div>
                <div className="pcap-stat-card accent-red">
                    <div className="stat-icon"><FaExclamationTriangle /></div>
                    <div className="stat-value">
                        {loadingAnalysis ? "..." : (analysis ? (analysis?.malicious_patterns?.length ?? "0") : "—")}
                    </div>
                    <div className="stat-label">Threat Indicators Detected</div>
                </div>
            </div>

            {/* ---- Analysis Error Banner ---- */}
            {analysisError && (
                <div className="pcap-error-banner" id="pcap-analysis-error">
                    <FaExclamationTriangle />
                    <span>{analysisError}</span>
                    {selectedCaptureId && (
                        <button onClick={() => {
                            fetchStats();
                            loadAnalysis(selectedCaptureId);
                        }} className="retry-btn">
                            Retry Analysis
                        </button>
                    )}
                </div>
            )}

            {/* ---- Loading Spinner for Analysis ---- */}
            {loadingAnalysis && (
                <div className="pcap-loading" id="pcap-analysis-loading">
                    <div className="pcap-spinner" />
                    <span className="loading-text">Analyzing capture #{selectedCaptureId} with DPI engine...</span>
                </div>
            )}

            {/* ---- Empty State if no captures exist ---- */}
            {!loadingCaptures && captures.length === 0 && !capturesError && (
                <div className="pcap-panel full-width">
                    <div className="empty-state">
                        <FaDatabase className="empty-icon" />
                        <h3>No PCAP Captures Available</h3>
                        <p>No packet capture files found in storage. Captures from live traffic or honeypots will automatically register here.</p>
                    </div>
                </div>
            )}

            {/* ---- Main Analysis Dashboard Content ---- */}
            {!loadingAnalysis && analysis && (
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
                                            formatter={(value, name) => [`${value} packets (${analysis.protocol_distribution.find(p => p.protocol === name)?.percentage || 0}%)`, name]}
                                        />
                                    </PieChart>
                                </ResponsiveContainer>
                            </div>
                        ) : (
                            <div className="empty-state">
                                <FaDatabase className="empty-icon" />
                                <p>No protocol data identified in capture</p>
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
                                <p>No IP packet traffic detected</p>
                            </div>
                        )}
                    </div>

                    {/* Malicious Patterns (Detections) */}
                    <div className="pcap-panel" id="malicious-patterns-panel">
                        <h3 className="panel-title">
                            <FaSkullCrossbones className="title-icon" /> Malicious Patterns Detected
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
                                <p>No heuristic malicious patterns detected</p>
                            </div>
                        )}
                    </div>

                    {/* Observed Network Indicators */}
                    <div className="pcap-panel" id="iocs-panel">
                        <h3 className="panel-title">
                            <FaBug className="title-icon" /> Observed Network Indicators (Artifacts)
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
                                <p>No observed network indicators extracted</p>
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
                                <p>No individual suspicious packets flagged</p>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
};

export default PacketAnalysis;

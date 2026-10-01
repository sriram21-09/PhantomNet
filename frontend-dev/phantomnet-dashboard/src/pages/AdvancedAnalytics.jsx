import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
    AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    BarChart, Bar, Cell, Legend
} from 'recharts';
import {
    FaChartLine, FaFileCsv, FaCamera, FaShieldAlt,
    FaSync, FaExclamationTriangle, FaInfoCircle, FaCalendarAlt, FaNetworkWired, FaTimes
} from 'react-icons/fa';
import { toPng } from 'html-to-image';
import '../Styles/pages/AdvancedAnalytics.css';

const SEVERITY_COLORS = {
    critical: '#ef4444',
    suspicious: '#f59e0b',
    benign: '#10b981'
};

const PROTOCOL_COLORS = ['#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#ec4899'];

const AdvancedAnalytics = () => {
    // Scope & Configuration
    const [timeRange, setTimeRange] = useState(7); // 7, 14, 30, 90 days
    const [autoRefresh, setAutoRefresh] = useState(true);
    const [lastUpdated, setLastUpdated] = useState(null);

    // Analytical Data State
    const [stats, setStats] = useState({
        totalEvents: 0,
        avgThreatScore: 0.0,
        criticalAlerts: 0,
        highSeverity: 0,
        mediumSeverity: 0,
        totalAnomalies: 0,
        uniqueIPs: 0,
        distribution: { critical: 0, suspicious: 0, benign: 0 },
        protocolDistribution: [],
        attackVectorDistribution: [],
        historicalBaseline: { days: 7, priorEvents: 0, delta: null }
    });
    const [trends, setTrends] = useState([]);

    // UI & Error Handling State
    const [isLoading, setIsLoading] = useState(true);
    const [isRefreshing, setIsRefreshing] = useState(false);
    const [error, setError] = useState(null);
    const [warning, setWarning] = useState(null);
    const [isExporting, setIsExporting] = useState(false);

    // Fetch synchronization references
    const isFetchingRef = useRef(false);
    const abortControllerRef = useRef(null);

    /**
     * Primary Analytical Data Fetcher
     * Queries /api/stats and /api/v1/analytics/trends with selected time window.
     */
    const fetchAnalyticsData = useCallback(async (isBackground = false) => {
        if (isFetchingRef.current) return;
        isFetchingRef.current = true;

        if (abortControllerRef.current) {
            abortControllerRef.current.abort();
        }
        const controller = new AbortController();
        abortControllerRef.current = controller;

        if (isBackground) {
            setIsRefreshing(true);
        } else {
            setIsLoading(true);
            setError(null);
        }

        try {
            const token = localStorage.getItem('token');
            const authHeaders = token ? { 'Authorization': `Bearer ${token}` } : {};

            // 1. Fetch consolidated statistics with time window
            const statsRes = await fetch(`/api/stats?days=${timeRange}`, {
                signal: controller.signal,
                headers: { ...authHeaders, 'Accept': 'application/json' }
            });

            if (!statsRes.ok) {
                if (statsRes.status === 401) {
                    throw new Error('Authentication required (401). Please log in to access analytics telemetry.');
                }
                if (statsRes.status === 403) {
                    throw new Error('Access denied (403). Analyst or Security Admin privileges required.');
                }
                if (statsRes.status >= 500) {
                    throw new Error(`Analytics service error (${statsRes.status}). Backend aggregation service failed.`);
                }
                throw new Error(`Failed to retrieve analytics metrics: HTTP ${statsRes.status}`);
            }

            const statsData = await statsRes.json();

            // 2. Fetch daily incident trends for the exact time window
            const trendsRes = await fetch(`/api/v1/analytics/trends?days=${timeRange}`, {
                signal: controller.signal,
                headers: { ...authHeaders, 'Accept': 'application/json' }
            });

            if (!trendsRes.ok) {
                throw new Error(`Failed to retrieve incident trends: HTTP ${trendsRes.status}`);
            }

            const trendsData = await trendsRes.json();

            // Guarded state updates with defensive fallback
            setStats({
                totalEvents: Number(statsData?.totalEvents) || 0,
                avgThreatScore: Number(statsData?.avgThreatScore) || 0.0,
                criticalAlerts: Number(statsData?.criticalAlerts) || 0,
                highSeverity: Number(statsData?.highSeverity) || 0,
                mediumSeverity: Number(statsData?.mediumSeverity) || 0,
                totalAnomalies: Number(statsData?.totalAnomalies) || 0,
                uniqueIPs: Number(statsData?.uniqueIPs) || 0,
                distribution: {
                    critical: Number(statsData?.distribution?.critical) || 0,
                    suspicious: Number(statsData?.distribution?.suspicious) || 0,
                    benign: Number(statsData?.distribution?.benign) || 0
                },
                protocolDistribution: Array.isArray(statsData?.protocolDistribution)
                    ? statsData.protocolDistribution
                    : [],
                attackVectorDistribution: Array.isArray(statsData?.attackVectorDistribution)
                    ? statsData.attackVectorDistribution
                    : [],
                historicalBaseline: statsData?.historicalBaseline || {
                    days: timeRange,
                    priorEvents: 0,
                    delta: null
                }
            });

            // Map authentic trends (zero-filled dates, NO synthetic mitigation curves)
            if (Array.isArray(trendsData)) {
                setTrends(trendsData.map(t => ({
                    time: t.date || 'Unknown',
                    incidents: Number(t.count) || 0
                })));
            } else {
                setTrends([]);
            }

            setLastUpdated(new Date());
            setError(null);
            setWarning(null);
        } catch (err) {
            if (err.name === 'AbortError') return;

            console.error('Advanced Analytics Fetch Error:', err);
            if (isBackground) {
                // Non-blocking warning on background refresh failure to preserve existing data
                setWarning(`Auto-refresh warning: ${err.message}. Retaining cached telemetry.`);
            } else {
                // Blocking error state on initial load or manual retry failure
                setError(err.message || 'An unexpected communication error occurred.');
            }
        } finally {
            isFetchingRef.current = false;
            setIsLoading(false);
            setIsRefreshing(false);
        }
    }, [timeRange]);

    // Initial fetch and timeRange watcher
    useEffect(() => {
        fetchAnalyticsData(false);
        return () => {
            if (abortControllerRef.current) {
                abortControllerRef.current.abort();
            }
        };
    }, [fetchAnalyticsData]);

    // Auto-refresh timer: 30s intervals with in-flight guard
    useEffect(() => {
        if (!autoRefresh) return;

        const intervalId = setInterval(() => {
            if (!isFetchingRef.current) {
                fetchAnalyticsData(true);
            }
        }, 30000);

        return () => clearInterval(intervalId);
    }, [autoRefresh, fetchAnalyticsData]);

    /**
     * CSV Export of Full Analytical Telemetry Dataset
     */
    const exportCSV = () => {
        const timestamp = new Date().toISOString();
        const lines = [];

        // Metadata Header
        lines.push('# PHANTOMNET ADVANCED ANALYTICS REPORT');
        lines.push(`# Generated At: ${timestamp}`);
        lines.push(`# Window: Last ${timeRange} Days`);
        lines.push('');

        // 1. KPI Summary
        lines.push('--- SUMMARY KEY PERFORMANCE INDICATORS ---');
        lines.push('Metric,Value,Unit,Notes');
        lines.push(`Total Incident Events,${stats.totalEvents},Count,Analyzed packet events in window`);
        lines.push(`Average Threat Score,${stats.avgThreatScore.toFixed(2)},Percent,Mean threat probability`);
        lines.push(`Critical Alerts,${stats.criticalAlerts},Count,Severity critical threshold crossings`);
        lines.push(`High Severity Events,${stats.highSeverity},Count,High risk anomaly detections`);
        lines.push(`Total Anomalies Detected,${stats.totalAnomalies},Count,Isolation Forest and RF outliers`);
        lines.push(`Unique Attacker IPs,${stats.uniqueIPs},Count,Distinct external source addresses`);
        lines.push(`Historical Baseline Delta,${stats.historicalBaseline.delta != null ? stats.historicalBaseline.delta + '%' : 'N/A'},Percentage,Compared to prior ${timeRange}-day period`);
        lines.push('MTTD (Mean Time To Detect),N/A,Minutes,Resolution lifecycle telemetry unavailable');
        lines.push('MTTR (Mean Time To Respond),N/A,Minutes,Resolution lifecycle telemetry unavailable');
        lines.push('');

        // 2. Daily Incident Trends
        lines.push('--- DAILY INCIDENT TRENDS ---');
        lines.push('Date,Incident Count');
        trends.forEach(t => {
            lines.push(`${t.time},${t.incidents}`);
        });
        lines.push('');

        // 3. Severity Distribution
        lines.push('--- SEVERITY CLASSIFICATION RATIO ---');
        lines.push('Classification,Event Count');
        lines.push(`Critical,${stats.distribution.critical}`);
        lines.push(`Suspicious,${stats.distribution.suspicious}`);
        lines.push(`Benign,${stats.distribution.benign}`);
        lines.push('');

        // 4. Attack Vector Distribution
        lines.push('--- ATTACK VECTOR CLASSIFICATION ---');
        lines.push('Attack Type,Event Count,Percentage');
        stats.attackVectorDistribution.forEach(v => {
            lines.push(`"${v.type}",${v.count},${v.percentage}%`);
        });
        lines.push('');

        // 5. Protocol Breakdown
        lines.push('--- PROTOCOL DISTRIBUTION ---');
        lines.push('Protocol,Event Count,Percentage');
        stats.protocolDistribution.forEach(p => {
            lines.push(`"${p.protocol}",${p.count},${p.percentage}%`);
        });

        const csvContent = lines.join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        const dateStr = new Date().toISOString().split('T')[0];

        link.setAttribute('href', url);
        link.setAttribute('download', `phantomnet_analytics_${timeRange}d_${dateStr}.csv`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    };

    /**
     * Dashboard Snapshot
     */
    const takeSnapshot = async () => {
        const element = document.getElementById('analytics-capture-area');
        if (!element) return;

        setIsExporting(true);
        try {
            const dataUrl = await toPng(element, {
                cacheBust: true,
                backgroundColor: '#020617',
                style: { padding: '24px' }
            });
            const link = document.createElement('a');
            link.download = `phantomnet_analytics_${Date.now()}.png`;
            link.href = dataUrl;
            link.click();
        } catch (snapErr) {
            console.error('Failed to capture snapshot:', snapErr);
        } finally {
            setIsExporting(false);
        }
    };

    // Recharts Custom Tooltip
    const CustomTooltip = ({ active, payload, label }) => {
        if (active && payload && payload.length) {
            return (
                <div className="custom-chart-tooltip" role="tooltip">
                    <p className="tooltip-label hud-font">{label}</p>
                    {payload.map((p, i) => (
                        <p key={i} className="tooltip-value" style={{ color: p.color || '#38bdf8' }}>
                            {p.name}: {Number(p.value).toLocaleString()}
                        </p>
                    ))}
                </div>
            );
        }
        return null;
    };

    // 1. Initial Loading State
    if (isLoading) {
        return (
            <div className="dashboard-wrapper loading-container" role="status" aria-live="polite">
                <div className="loading-spinner" aria-hidden="true"></div>
                <div className="loading-text hud-font">RETRIEVING ANALYTICAL TELEMETRY...</div>
                <p className="loading-subtext text-dim">Aggregating historical event records across sensor nodes</p>
            </div>
        );
    }

    // 2. Initial Blocking Error State
    if (error && stats.totalEvents === 0) {
        return (
            <div className="dashboard-wrapper error-container" role="alert">
                <div className="error-card pro-card">
                    <FaExclamationTriangle className="error-icon" aria-hidden="true" />
                    <h2 className="error-title hud-font">Analytics Telemetry Error</h2>
                    <p className="error-message">{error}</p>
                    <button
                        className="retry-btn hud-font"
                        onClick={() => fetchAnalyticsData(false)}
                        aria-label="Retry loading analytical telemetry"
                    >
                        <FaSync /> RETRY REQUEST
                    </button>
                </div>
            </div>
        );
    }

    // Baseline Trend Formatting (Accessible & Authentic)
    const baselineDelta = stats.historicalBaseline?.delta;
    let trendBadge = null;
    if (baselineDelta !== null && baselineDelta !== undefined) {
        if (baselineDelta > 0) {
            trendBadge = (
                <span className="card-trend trend-warn" aria-label={`Increase of ${baselineDelta}% compared with prior ${timeRange} day period`}>
                    <span aria-hidden="true">▲ +{baselineDelta}%</span>
                    <span className="trend-text">vs prior {timeRange}d</span>
                </span>
            );
        } else if (baselineDelta < 0) {
            trendBadge = (
                <span className="card-trend trend-down" aria-label={`Decrease of ${Math.abs(baselineDelta)}% compared with prior ${timeRange} day period`}>
                    <span aria-hidden="true">▼ {baselineDelta}%</span>
                    <span className="trend-text">vs prior {timeRange}d</span>
                </span>
            );
        } else {
            trendBadge = (
                <span className="card-trend trend-neutral" aria-label={`No change compared with prior ${timeRange} day period`}>
                    <span aria-hidden="true">▬ 0.0%</span>
                    <span className="trend-text">vs prior {timeRange}d</span>
                </span>
            );
        }
    } else {
        trendBadge = (
            <span className="card-trend trend-neutral" aria-label="No historical prior period data available for comparison">
                <span className="trend-text">Baseline unavailable</span>
            </span>
        );
    }

    return (
        <main className="analytics-wrapper dashboard-wrapper" id="analytics-capture-area">
            {/* Header Section */}
            <header className="dashboard-header">
                <div className="header-content">
                    <div className="header-title">
                        <div className="dashboard-header-premium">
                            <h1 className="dashboard-title glow-text">Advanced Analytics</h1>
                            <p className="dashboard-subtitle text-dim">
                                HISTORICAL SECURITY ANALYTICS & SOC TREND REPORTING
                            </p>
                        </div>
                    </div>

                    {/* Controls & Actions */}
                    <div className="header-actions">
                        {/* Time Range Selector */}
                        <div className="time-range-controls" role="group" aria-label="Analytical time range selection">
                            <span className="control-label hud-font">
                                <FaCalendarAlt aria-hidden="true" /> WINDOW:
                            </span>
                            {[7, 14, 30, 90].map(days => (
                                <button
                                    key={days}
                                    type="button"
                                    className={`range-btn hud-font ${timeRange === days ? 'active' : ''}`}
                                    onClick={() => setTimeRange(days)}
                                    aria-pressed={timeRange === days}
                                    aria-label={`Show analytics for the last ${days} days`}
                                >
                                    {days}D
                                </button>
                            ))}
                        </div>

                        {/* Refresh & Export Controls */}
                        <div className="export-panel">
                            <button
                                type="button"
                                className={`refresh-btn hud-font ${isRefreshing ? 'spinning' : ''}`}
                                onClick={() => fetchAnalyticsData(false)}
                                disabled={isRefreshing}
                                aria-label="Manually refresh analytics data"
                                title="Manually refresh analytics"
                            >
                                <FaSync aria-hidden="true" /> {isRefreshing ? 'SYNCING...' : 'REFRESH'}
                            </button>

                            <button
                                type="button"
                                className={`auto-refresh-toggle hud-font ${autoRefresh ? 'active' : ''}`}
                                onClick={() => setAutoRefresh(prev => !prev)}
                                aria-pressed={autoRefresh}
                                aria-label={autoRefresh ? 'Disable 30-second automatic refresh' : 'Enable 30-second automatic refresh'}
                                title="Toggle 30-second background polling"
                            >
                                AUTO: {autoRefresh ? '30S' : 'OFF'}
                            </button>

                            <button
                                type="button"
                                className="export-btn hud-font"
                                onClick={exportCSV}
                                aria-label="Export analytics dataset to CSV file"
                            >
                                <FaFileCsv aria-hidden="true" /> CSV EXPORT
                            </button>

                            <button
                                type="button"
                                className="export-btn hud-font"
                                onClick={takeSnapshot}
                                disabled={isExporting}
                                aria-label="Capture PNG screenshot of analytics dashboard"
                            >
                                <FaCamera aria-hidden="true" /> {isExporting ? 'CAPTURING...' : 'SNAPSHOT'}
                            </button>
                        </div>
                    </div>
                </div>

                {/* Non-blocking Warning Banner */}
                {warning && (
                    <div className="warning-banner" role="alert" aria-live="polite">
                        <FaExclamationTriangle className="warning-icon" aria-hidden="true" />
                        <span className="warning-text">{warning}</span>
                        <button
                            type="button"
                            className="warning-dismiss"
                            onClick={() => setWarning(null)}
                            aria-label="Dismiss warning notification"
                        >
                            <FaTimes aria-hidden="true" />
                        </button>
                    </div>
                )}

                {/* Status indicator bar */}
                <div className="analytics-status-bar">
                    <span className="status-item">
                        <span className="status-dot online" aria-hidden="true"></span>
                        <span>Mode: Historical SOC Telemetry ({timeRange}d window)</span>
                    </span>
                    {lastUpdated && (
                        <span className="status-item text-dim">
                            Last synced: {lastUpdated.toLocaleTimeString()}
                        </span>
                    )}
                </div>
            </header>

            {/* Section 1: KPI Telemetry Overview */}
            <section aria-labelledby="kpi-heading">
                <h2 id="kpi-heading" className="sr-only">Key Performance Indicators</h2>
                <div className="analytics-metrics-grid">
                    {/* KPI 1: Total Incidents */}
                    <div className="analytics-card-premium pro-card" style={{ '--card-accent': '#3b82f6' }}>
                        <div className="card-label hud-font">
                            <FaChartLine aria-hidden="true" /> TOTAL LOGGED EVENTS
                        </div>
                        <div className="card-value" aria-label={`${stats.totalEvents.toLocaleString()} total logged events`}>
                            {stats.totalEvents.toLocaleString()}
                        </div>
                        {trendBadge}
                    </div>

                    {/* KPI 2: Average Threat Score */}
                    <div className="analytics-card-premium pro-card" style={{ '--card-accent': '#8b5cf6' }}>
                        <div className="card-label hud-font">
                            <FaShieldAlt aria-hidden="true" /> AVG THREAT SCORE
                        </div>
                        <div className="card-value" aria-label={`Average threat score ${stats.avgThreatScore.toFixed(1)} percent`}>
                            {stats.avgThreatScore.toFixed(1)}%
                        </div>
                        <div className="card-trend trend-neutral">
                            <span className="trend-text">Mean risk across window</span>
                        </div>
                    </div>

                    {/* KPI 3: High Severity & Critical Events */}
                    <div className="analytics-card-premium pro-card" style={{ '--card-accent': '#ef4444' }}>
                        <div className="card-label hud-font">
                            <FaExclamationTriangle aria-hidden="true" /> HIGH & CRITICAL ALERTS
                        </div>
                        <div className="card-value" aria-label={`${((stats.criticalAlerts || 0) + (stats.highSeverity || 0)).toLocaleString()} critical and high severity alerts`}>
                            {((stats.criticalAlerts || 0) + (stats.highSeverity || 0)).toLocaleString()}
                        </div>
                        <div className="card-trend trend-warn">
                            <span className="trend-text">{stats.criticalAlerts} Critical / {stats.highSeverity} High</span>
                        </div>
                    </div>

                    {/* KPI 4: Unique Attackers */}
                    <div className="analytics-card-premium pro-card" style={{ '--card-accent': '#10b981' }}>
                        <div className="card-label hud-font">
                            <FaNetworkWired aria-hidden="true" /> UNIQUE ATTACKER IPS
                        </div>
                        <div className="card-value" aria-label={`${stats.uniqueIPs.toLocaleString()} unique attacker IP addresses`}>
                            {stats.uniqueIPs.toLocaleString()}
                        </div>
                        <div className="card-trend trend-neutral">
                            <span className="trend-text">Distinct external sources</span>
                        </div>
                    </div>
                </div>

                {/* Truthful Incident Lifecycle Note (ADV-DEF-01) */}
                <div className="lifecycle-notice-card pro-card" role="note">
                    <div className="lifecycle-notice-content">
                        <FaInfoCircle className="notice-icon" aria-hidden="true" />
                        <div>
                            <span className="hud-font notice-title">INCIDENT LIFECYCLE TELEMETRY (MTTD / MTTR): </span>
                            <span className="notice-status">UNAVAILABLE (N/A)</span>
                            <p className="notice-description text-dim">
                                Authoritative incident resolution timestamps are not tracked in sensor cluster event logs.
                                PhantomNet strictly enforces data authenticity and does not fabricate MTTR or MTTD values.
                            </p>
                        </div>
                    </div>
                </div>
            </section>

            {/* Section 2: Main Analytical Charts */}
            <section aria-labelledby="charts-heading" className="analytics-charts-section">
                <h2 id="charts-heading" className="sr-only">Analytical Charts and Threat Breakdown</h2>

                <div className="analytics-charts-grid">
                    {/* Chart 1: Global Incident Volume Trends (Authentic Time Series, NO fake mitigation curves) */}
                    <div className="chart-card pro-card chart-container-large">
                        <div className="chart-header">
                            <h3 className="chart-title hud-font">
                                <FaChartLine aria-hidden="true" /> Incident Volume Trends ({timeRange}-Day Daily Distribution)
                            </h3>
                            <span className="chart-badge text-dim">Zero-filled continuous dates</span>
                        </div>
                        {trends.length === 0 || stats.totalEvents === 0 ? (
                            <div className="chart-empty-state" role="status">
                                <p>No incident activity recorded in the selected {timeRange}-day window.</p>
                            </div>
                        ) : (
                            <div role="region" aria-label={`Area chart displaying daily incident volumes across the last ${timeRange} days`} style={{ width: '100%', height: 300 }}>
                                <ResponsiveContainer width="100%" height={300}>
                                    <AreaChart data={trends} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                                        <defs>
                                            <linearGradient id="colorIncidents" x1="0" y1="0" x2="0" y2="1">
                                                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                                                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                                            </linearGradient>
                                        </defs>
                                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
                                        <XAxis
                                            dataKey="time"
                                            stroke="#64748b"
                                            fontSize={11}
                                            tickLine={false}
                                            axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                                        />
                                        <YAxis
                                            stroke="#64748b"
                                            fontSize={11}
                                            tickLine={false}
                                            axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                                            tickFormatter={(val) => val >= 1000 ? `${(val / 1000).toFixed(0)}k` : val}
                                        />
                                        <Tooltip content={<CustomTooltip />} />
                                        <Area
                                            type="monotone"
                                            dataKey="incidents"
                                            stroke="#3b82f6"
                                            fillOpacity={1}
                                            fill="url(#colorIncidents)"
                                            strokeWidth={2}
                                            name="Logged Events"
                                        />
                                    </AreaChart>
                                </ResponsiveContainer>
                            </div>
                        )}
                    </div>

                    {/* Chart 2: Severity Classification Ratio */}
                    <div className="chart-card pro-card">
                        <div className="chart-header">
                            <h3 className="chart-title hud-font">
                                <FaShieldAlt aria-hidden="true" /> Severity Classification
                            </h3>
                            <span className="chart-badge text-dim">Current Window</span>
                        </div>
                        <div role="region" aria-label="Bar chart showing distribution of critical, suspicious, and benign classifications" style={{ width: '100%', height: 300 }}>
                            <ResponsiveContainer width="100%" height={300}>
                                <BarChart
                                    data={[
                                        { name: 'Critical', count: stats.distribution.critical, color: SEVERITY_COLORS.critical },
                                        { name: 'Suspicious', count: stats.distribution.suspicious, color: SEVERITY_COLORS.suspicious },
                                        { name: 'Benign', count: stats.distribution.benign, color: SEVERITY_COLORS.benign }
                                    ]}
                                    margin={{ top: 20, right: 20, left: -10, bottom: 0 }}
                                >
                                    <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                                    <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                                    <YAxis
                                        stroke="#64748b"
                                        fontSize={11}
                                        tickLine={false}
                                        tickFormatter={(val) => val >= 1000 ? `${(val / 1000).toFixed(0)}k` : val}
                                    />
                                    <Tooltip content={<CustomTooltip />} />
                                    <Bar dataKey="count" radius={[4, 4, 0, 0]} name="Events">
                                        <Cell fill={SEVERITY_COLORS.critical} />
                                        <Cell fill={SEVERITY_COLORS.suspicious} />
                                        <Cell fill={SEVERITY_COLORS.benign} />
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    {/* Chart 3: Authentic Attack Vector Distribution (ADV-DEF-07) */}
                    <div className="chart-card pro-card">
                        <div className="chart-header">
                            <h3 className="chart-title hud-font">
                                <FaNetworkWired aria-hidden="true" /> Attack Vector Breakdown
                            </h3>
                            <span className="chart-badge text-dim">Authoritative Types</span>
                        </div>
                        {stats.attackVectorDistribution.length === 0 ? (
                            <div className="chart-empty-state" role="status">
                                <p>No classified attack vectors recorded in the selected window.</p>
                            </div>
                        ) : (
                            <div role="region" aria-label="Bar chart showing distribution of detected attack vectors" style={{ width: '100%', height: 300 }}>
                                <ResponsiveContainer width="100%" height={300}>
                                    <BarChart
                                        data={stats.attackVectorDistribution.slice(0, 6)}
                                        layout="vertical"
                                        margin={{ top: 10, right: 30, left: 40, bottom: 0 }}
                                    >
                                        <CartesianGrid stroke="rgba(255,255,255,0.05)" horizontal={false} />
                                        <XAxis
                                            type="number"
                                            stroke="#64748b"
                                            fontSize={10}
                                            tickFormatter={(val) => val >= 1000 ? `${(val / 1000).toFixed(0)}k` : val}
                                        />
                                        <YAxis
                                            type="category"
                                            dataKey="type"
                                            stroke="#94a3b8"
                                            fontSize={10}
                                            tickLine={false}
                                            width={80}
                                        />
                                        <Tooltip content={<CustomTooltip />} />
                                        <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} name="Events">
                                            {stats.attackVectorDistribution.slice(0, 6).map((entry, idx) => (
                                                <Cell key={`cell-${idx}`} fill={PROTOCOL_COLORS[idx % PROTOCOL_COLORS.length]} />
                                            ))}
                                        </Bar>
                                    </BarChart>
                                </ResponsiveContainer>
                            </div>
                        )}
                    </div>

                    {/* Chart 4: Protocol Distribution Breakdown */}
                    <div className="chart-card pro-card">
                        <div className="chart-header">
                            <h3 className="chart-title hud-font">
                                <FaNetworkWired aria-hidden="true" /> Transport Protocol Volume
                            </h3>
                            <span className="chart-badge text-dim">L4/L7 Distribution</span>
                        </div>
                        {stats.protocolDistribution.length === 0 ? (
                            <div className="chart-empty-state" role="status">
                                <p>No protocol activity recorded in the selected window.</p>
                            </div>
                        ) : (
                            <div role="region" aria-label="Bar chart showing breakdown of network traffic by protocol" style={{ width: '100%', height: 300 }}>
                                <ResponsiveContainer width="100%" height={300}>
                                    <BarChart
                                        data={stats.protocolDistribution.slice(0, 6)}
                                        margin={{ top: 20, right: 20, left: -10, bottom: 0 }}
                                    >
                                        <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                                        <XAxis dataKey="protocol" stroke="#64748b" fontSize={11} tickLine={false} />
                                        <YAxis
                                            stroke="#64748b"
                                            fontSize={11}
                                            tickLine={false}
                                            tickFormatter={(val) => val >= 1000 ? `${(val / 1000).toFixed(0)}k` : val}
                                        />
                                        <Tooltip content={<CustomTooltip />} />
                                        <Bar dataKey="count" fill="#8b5cf6" radius={[4, 4, 0, 0]} name="Packets">
                                            {stats.protocolDistribution.slice(0, 6).map((_, idx) => (
                                                <Cell key={`pcell-${idx}`} fill={PROTOCOL_COLORS[idx % PROTOCOL_COLORS.length]} />
                                            ))}
                                        </Bar>
                                    </BarChart>
                                </ResponsiveContainer>
                            </div>
                        )}
                    </div>
                </div>
            </section>
        </main>
    );
};

export default AdvancedAnalytics;

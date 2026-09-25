import React, { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import { FaChartLine } from "react-icons/fa";

import MetricCard from "../components/MetricCard";
import LoadingSpinner from "../components/LoadingSpinner";
import HoneypotStatus from "../components/Honeypotstatus";
import AttackTimeline from "../components/AttackTimeline";
import ProtocolChart from "../components/ProtocolChart";
import TopAttackers from "../components/TopAttackers";
import OptimizedThreatLevel from "../components/OptimizedThreatLevel";
import PremiumGaugeCard from "../components/PremiumGaugeCard";
import PremiumMetricCard from "../components/PremiumMetricCard";
import CyberMeshMap from "../components/CyberMeshMap";
import TrendsChart from "../components/TrendsChart";
import WelcomeModal from "../components/WelcomeModal";
import SentinelStatsWidget from "../components/SentinelStatsWidget";
import { useRealTime } from "../context/RealTimeContext";
import { fetchThreatMetrics, fetchSentinelStats } from "../services/api";
import { Button } from "../components/ui/button";
import "../Styles/pages/Dashboard.css";

const Dashboard = () => {
  const [dataMode, setDataMode] = useState("all"); // 'all' | 'live' | 'test'
  const [stats, setStats] = useState(null);
  const [threatMetrics, setThreatMetrics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Sentinel Stats State
  const [sentinelStats, setSentinelStats] = useState(null);
  const [sentinelLoading, setSentinelLoading] = useState(true);
  const [sentinelError, setSentinelError] = useState(null);

  // WebSocket real-time data
  const realTime = useRealTime();
  const wsMetrics = realTime?.metrics;
  const wsConnected = realTime?.isConnected;

  // Merge WebSocket metrics into stats for real-time updates (only in 'all' or 'live' mode)
  useEffect(() => {
    if (wsMetrics && stats && dataMode !== "test") {
      setStats((prev) => ({
        ...prev,
        totalEvents: wsMetrics.total_events ?? wsMetrics.totalEvents ?? prev.totalEvents,
        uniqueIPs: wsMetrics.unique_ips ?? wsMetrics.uniqueIPs ?? prev.uniqueIPs,
        activeHoneypots: wsMetrics.active_honeypots ?? wsMetrics.activeHoneypots ?? prev.activeHoneypots,
        avgThreatScore: wsMetrics.avg_threat_score ?? wsMetrics.avgThreatScore ?? prev.avgThreatScore,
        criticalAlerts: wsMetrics.critical_alerts ?? wsMetrics.criticalAlerts ?? prev.criticalAlerts,
      }));
    }
  }, [wsMetrics]);

  // Unified Stats Fetch + Polling backed by selected dataMode
  useEffect(() => {
    let mounted = true;
    const fetchStats = async (isInitial = false) => {
      try {
        if (isInitial) setLoading(true);
        const res = await fetch(`/api/stats?mode=${dataMode}`);
        if (!res.ok) throw new Error("Failed to fetch stats");
        const data = await res.json();

        if (mounted) {
          setStats(data);
          setThreatMetrics(data);
          setError(null);
        }
      } catch (err) {
        if (mounted) setError(err.message);
      } finally {
        if (isInitial && mounted) setLoading(false);
      }
    };

    fetchStats(true);
    const pollInterval = wsConnected ? 20000 : 8000;
    const interval = setInterval(() => fetchStats(false), pollInterval);

    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [dataMode, wsConnected]);

  // Sentinel Stats Fetch + Polling
  useEffect(() => {
    const loadSentinelStats = async (isInitial = false) => {
      try {
        if (isInitial) setSentinelLoading(true);
        const data = await fetchSentinelStats();
        setSentinelStats(data);
        setSentinelError(null);
      } catch (err) {
        setSentinelError(err.message);
      } finally {
        if (isInitial) setSentinelLoading(false);
      }
    };

    loadSentinelStats(true);
    const interval = setInterval(() => loadSentinelStats(false), 10000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard-wrapper">
      <WelcomeModal />
      {/* Dashboard Header */}
      <div className="dashboard-header">
        <div className="header-content">
          <div className="header-title">
            <div className="dashboard-header-premium">
              <h1 className="dashboard-title glow-text">Command Center</h1>
              <p className="dashboard-subtitle text-dim">GLOBAL THREAT DEFENSE MESH | LIVE FEED SYNCHRONIZED</p>
            </div>
          </div>
          
          {/* Dataset Scope Selector */}
          <div className="data-mode-container">
            <span className="mode-label">DATASET SCOPE:</span>
            <div className="data-mode-pills">
              <button
                className={`data-mode-btn ${dataMode === "all" ? "active" : ""}`}
                onClick={() => setDataMode("all")}
                title="Complete dataset: mixed live honeypot telemetry and baseline benchmarks"
              >
                All Events (Mixed)
              </button>
              <button
                className={`data-mode-btn live ${dataMode === "live" ? "active" : ""}`}
                onClick={() => setDataMode("live")}
                title="Strictly verified honeypot sensor telemetry (SSH, HTTP, FTP, SMTP)"
              >
                <span className="live-indicator-dot" /> Live Honeypots Only
              </button>
              <button
                className={`data-mode-btn ${dataMode === "test" ? "active" : ""}`}
                onClick={() => setDataMode("test")}
                title="Synthetic benchmark TCP dataset (RFC 5737 / stress testing)"
              >
                Test / Benchmark
              </button>
            </div>
          </div>

          <Link to="/features">
            <Button className="analysis-btn">
              <FaChartLine />
              <span>Analysis</span>
            </Button>
          </Link>
        </div>
      </div>

      {/* Telemetry Scope Disclosure Bar */}
      <div className="telemetry-disclosure-bar">
        <span className="disclosure-badge">
          {dataMode === "live" ? "VERIFIED SENSORS" : dataMode === "test" ? "SYNTHETIC BENCHMARK" : "MIXED TELEMETRY"}
        </span>
        <span className="disclosure-text">
          {dataMode === "live"
            ? "Showing 100% verified honeypot sensor telemetry (SSH, HTTP, FTP, SMTP) — zero synthetic records."
            : dataMode === "test"
            ? "Showing baseline TCP benchmark dataset (RFC 5737 / high-throughput stress evaluation)."
            : "Dashboard includes live honeypot sensors (SSH, HTTP, FTP, SMTP) and controlled benchmark baseline; source classification is displayed where applicable."}
        </span>
      </div>

      {loading && <LoadingSpinner />}
      {error && <div className="error-banner">{error}</div>}

      {!loading && stats && (
        <>
          {/* Metrics Row */}
          <div className="metrics-grid">
            <PremiumMetricCard
              title="Total Events"
              value={stats.totalEvents}
              variant="blue"
              subtitle="GLOBAL AGGREGATE"
              status="STABLE"
              progress={75}
            />
            <PremiumMetricCard
              title="Unique IPs"
              value={stats.uniqueIPs}
              variant="cyan"
              subtitle="IDENTIFIED THREATS"
              status="ANALYZED"
              progress={60}
            />
            <PremiumMetricCard
              title="Active Nodes"
              value={`${stats.activeHoneypots} / 4`}
              variant="green"
              subtitle="HONEYPOT MESH"
              status="ONLINE"
              progress={(stats.activeHoneypots / 4) * 100}
            />
            <PremiumMetricCard
              title="Threat Score"
              value={`${stats.avgThreatScore}%`}
              variant="orange"
              subtitle="RISK INDEX"
              status="CAUTION"
              progress={stats.avgThreatScore}
            />
            <PremiumMetricCard
              title="Critical Alerts"
              value={stats.criticalAlerts}
              variant="red"
              subtitle="IMMEDIATE ACTION"
              status="ALERT"
              progress={stats.criticalAlerts > 0 ? 90 : 0}
            />
          </div>

          {/* Sentinel Playbook Intelligence */}
          <SentinelStatsWidget
            stats={sentinelStats}
            loading={sentinelLoading}
            error={sentinelError}
          />

          {/* Main Visual Intelligence Section */}
          <div className="dashboard-content">
            {/* Critical Vector Analysis Row */}
            <div className="noc-row main">
              <div className="mesh-container">
                <CyberMeshMap />
              </div>
              <div className="threat-intelligence-group">
                {threatMetrics || stats ? (
                  <OptimizedThreatLevel threatLevel={threatMetrics?.avgThreatScore ?? stats?.avgThreatScore ?? 0} />
                ) : (
                  <div className="skeleton-card"></div>
                )}
                {threatMetrics || stats ? (
                  <PremiumGaugeCard
                    title="Anomaly Score"
                    value={`${Math.round(threatMetrics?.avgAnomalyScore ?? stats?.avgAnomalyScore ?? 0)}% RISK`}
                    progress={Math.round(threatMetrics?.avgAnomalyScore ?? stats?.avgAnomalyScore ?? 0)}
                    variant="orange"
                    subtitle="SENSORY FEED"
                    status={(threatMetrics?.avgAnomalyScore ?? stats?.avgAnomalyScore ?? 0) > 70 ? "CRITICAL" : (threatMetrics?.avgAnomalyScore ?? stats?.avgAnomalyScore ?? 0) > 40 ? "WARNING" : "OPTIMAL"}
                  />
                ) : (
                  <div className="skeleton-card"></div>
                )}
              </div>
            </div>

            {/* Temporal & Protocol Analytics Row */}
            <div className="noc-row analytics">
              <AttackTimeline mode={dataMode} />
              <ProtocolChart data={stats?.protocolDistribution} />
            </div>

            {/* Honeypot Network Status — above Top Threat Vectors */}
            <HoneypotStatus />

            {/* Threat Manifest Row */}
            <div className="noc-row status">
              <TopAttackers mode={dataMode} />
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default Dashboard;

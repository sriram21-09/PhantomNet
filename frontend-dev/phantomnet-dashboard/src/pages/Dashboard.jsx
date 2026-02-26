import React, { useEffect, useState } from "react";
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
import { fetchThreatMetrics } from "../services/api";
import { Button } from "../components/ui/button";
import "../Styles/pages/Dashboard.css";

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [threatMetrics, setThreatMetrics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Existing Stats Fetch
  useEffect(() => {
    const fetchStats = async () => {
      try {
        setLoading(true);
        const res = await fetch("/api/stats");
        if (!res.ok) throw new Error("Failed to fetch stats");
        const data = await res.json();

        setStats({
          totalEvents: data.totalEvents ?? 0,
          uniqueIPs: data.uniqueIPs ?? 0,
          activeHoneypots: data.activeHoneypots ?? 0,
          avgThreatScore: data.avgThreatScore ?? 0,
          criticalAlerts: data.criticalAlerts ?? 0,
        });
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
  }, []);

  // Threat Metrics Live API + Auto Refresh
  useEffect(() => {
    const loadThreatMetrics = async () => {
      try {
        const data = await fetchThreatMetrics();
        setThreatMetrics(data);
      } catch (err) {
        console.error("Threat metrics fetch error:", err);
      }
    };

    loadThreatMetrics();
    const interval = setInterval(loadThreatMetrics, 5000);

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
              <div className="header-badge hud-font">NODE_DELTA_V.2</div>
              <h1 className="dashboard-title glow-text">Command Center</h1>
              <p className="dashboard-subtitle text-dim">GLOBAL THREAT DEFENSE MESH | LIVE FEED SYNCHRONIZED</p>
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
              value={stats.activeHoneypots}
              variant="green"
              subtitle="SECURE MESH"
              status="ONLINE"
              progress={100}
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

          {/* Main Visual Intelligence Section */}
          <div className="dashboard-content">
            {/* Critical Vector Analysis Row */}
            <div className="noc-row main">
              <div className="mesh-container">
                <CyberMeshMap />
              </div>
              <div className="threat-intelligence-group">
                {threatMetrics ? (
                  <OptimizedThreatLevel threatLevel={threatMetrics.threatLevel} />
                ) : (
                  <div className="skeleton-card"></div>
                )}
                {threatMetrics ? (
                  <PremiumGaugeCard
                    title="Anomaly Score"
                    value={`${Math.round((threatMetrics?.anomalyScore || 0) * 100)}% RISK`}
                    progress={Math.round((threatMetrics?.anomalyScore || 0) * 100)}
                    variant="orange"
                    subtitle="SENSORY FEED"
                    status="IDENTIFYING"
                  />
                ) : (
                  <div className="skeleton-card"></div>
                )}
              </div>
            </div>

            {/* Temporal & Protocol Analytics Row */}
            <div className="noc-row analytics">
              <AttackTimeline />
              <ProtocolChart />
            </div>

            {/* Asset Status & Threat Manifest Row */}
            <div className="noc-row status">
              <HoneypotStatus />
              <TopAttackers />
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default Dashboard;

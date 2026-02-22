import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { FaChartLine } from "react-icons/fa";

import MetricCard from "../components/MetricCard";
import LoadingSpinner from "../components/LoadingSpinner";
import HoneypotStatus from "../components/Honeypotstatus";
import NetworkVisualization from "../components/NetworkVisualization";
import AnomalyGaugeCard from "../components/AnomalyGaugeCard";
import AttackTimeline from "../components/AttackTimeline";
import ProtocolChart from "../components/ProtocolChart";
import TopAttackers from "../components/TopAttackers";
import TrendsChart from "../components/TrendsChart";
import CyberMeshMap from "../components/CyberMeshMap";
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
            <MetricCard title="Total Events" value={stats.totalEvents} variant="blue" />
            <MetricCard title="Unique IPs" value={stats.uniqueIPs} variant="cyan" />
            <MetricCard title="Active Nodes" value={stats.activeHoneypots} variant="green" />
            <MetricCard title="Threat Score" value={`${stats.avgThreatScore}%`} variant="orange" />
            <MetricCard title="Critical Alerts" value={stats.criticalAlerts} variant="red" />
          </div>

          {/* New Priority Section: Network & Status */}
          <div className="priority-section">
            <div className="priority-main">
              <NetworkVisualization />
            </div>
            <div className="priority-side pro-card">
              <HoneypotStatus />
            </div>
          </div>

          {/* Global Threat Mesh Section */}
          <div className="mesh-row">
            <CyberMeshMap />
          </div>

          {/* Core Analytics Row */}
          <div className="analytics-row">
            <div className="analytics-main pro-card">
              <TrendsChart />
            </div>
            <div className="analytics-side pro-card">
              <ProtocolChart />
            </div>
          </div>

          {/* Legacy Timeline Row */}
          <div className="analytics-row">
            <div className="analytics-full pro-card">
              <AttackTimeline />
            </div>
          </div>

          {/* Threat Intelligence & Detailed Panels */}
          <div className="panels-grid">
            <div className="panel threat-intel-panel">
              <div className="threat-intel-grid">
                <div className="threat-slot pro-card">
                  {threatMetrics ? (
                    <MetricCard
                      title="Threat Level"
                      value={`${threatMetrics.threatLevel}%`}
                      variant={
                        threatMetrics.threatLevel < 40
                          ? "green"
                          : threatMetrics.threatLevel < 70
                            ? "orange"
                            : "red"
                      }
                    />
                  ) : (
                    <div className="skeleton-card"></div>
                  )}
                </div>
                <div className="threat-slot pro-card">
                  {threatMetrics ? (
                    <AnomalyGaugeCard anomalyScore={threatMetrics.anomalyScore} />
                  ) : (
                    <div className="skeleton-card"></div>
                  )}
                </div>
              </div>
            </div>
            <div className="panel attackers-panel">
              <TopAttackers />
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default Dashboard;

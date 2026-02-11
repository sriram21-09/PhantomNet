import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { FaChartLine } from "react-icons/fa";

import MetricCard from "../components/MetricCard";
import LoadingSpinner from "../components/LoadingSpinner";
import HoneypotStatus from "../components/Honeypotstatus";
import NetworkVisualization from "../components/NetworkVisualization";
import AnomalyGaugeCard from "../components/AnomalyGaugeCard";
import { threatMetrics } from "../mocks/threatData";
import { Button } from "../components/ui/button";
import "./Dashboard.css";

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

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

  return (
    <div className="dashboard-wrapper">
      {/* Dashboard Header */}
      <div className="dashboard-header">
        <div className="header-content">
          <div className="header-title">
            <div className="title-badge">LIVE</div>
            <h1>Command Center</h1>
            <p>AI-Powered Threat Defense • Real-time Monitoring</p>
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

          {/* Threat Metrics Section */}
          <div className="metrics-grid">
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
            <AnomalyGaugeCard anomalyScore={threatMetrics.anomalyScore} />
          </div>

          {/* Main Panels */}
          <div className="panels-grid">
            <div className="panel network-panel">
              <NetworkVisualization />
            </div>
            <div className="panel honeypot-panel">
              <HoneypotStatus />
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default Dashboard;

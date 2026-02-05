import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import MetricCard from "../components/MetricCard";
import LoadingSpinner from "../components/LoadingSpinner";
import HoneypotStatus from "../components/Honeypotstatus";
import NetworkVisualization from "../components/NetworkVisualization";
import "./Dashboard.css";

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        setLoading(true);
        const res = await fetch("http://127.0.0.1:8000/api/stats");
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
    <div className="dashboard-container">
      {/* HEADER */}
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <p>Live system overview and security metrics</p>

        <Link to="/dashboard/features">
          <button className="primary-btn">View Feature Analysis</button>
        </Link>
      </div>

      {loading && <LoadingSpinner />}
      {error && <p className="error-text">{error}</p>}

      {!loading && stats && (
        <div className="metrics-section">
          <MetricCard title="Total Events" value={stats.totalEvents} variant="blue" />
          <MetricCard title="Unique IPs" value={stats.uniqueIPs} variant="cyan" />
          <MetricCard title="Active Honeypots" value={stats.activeHoneypots} variant="green" />
          <MetricCard
            title="Avg Threat Score"
            value={`${stats.avgThreatScore}%`}
            variant="orange"
          />
          <MetricCard
            title="Critical Alerts"
            value={stats.criticalAlerts}
            variant="red"
          />
        </div>
      )}

      <HoneypotStatus />
      <NetworkVisualization />
    </div>
  );
};

export default Dashboard;

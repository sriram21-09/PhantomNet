/**
 * Dashboard Page
 * --------------
 * Main overview page showing metrics, honeypot status,
 * and network visualization.
 */
import React, { useEffect, useState, useContext } from "react";
import { Link } from "react-router-dom";

import MetricCard from "../components/MetricCard";
import LoadingSpinner from "../components/LoadingSpinner";
import HoneypotStatus from "../components/Honeypotstatus";
import NetworkVisualization from "../components/NetworkVisualization";
import { ThemeContext } from "../context/ThemeContext";

const Dashboard = () => {
  const { theme } = useContext(ThemeContext); // ✅ THEME

  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  /* =========================
     FETCH DASHBOARD STATS
  ========================== */
  useEffect(() => {
    const fetchStats = async () => {
      try {
        setLoading(true);
        setError(null);

        const response = await fetch("http://127.0.0.1:8000/api/stats");
        if (!response.ok) throw new Error("Failed to fetch dashboard stats");

        const data = await response.json();

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

  const isEmptyStats =
    stats &&
    stats.totalEvents === 0 &&
    stats.uniqueIPs === 0 &&
    stats.criticalAlerts === 0;

  /* =========================
     UI
  ========================== */
  return (
    <div className={`page-container dashboard-container ${theme}`}>
      {/* HEADER */}
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <p>This is the PhantomNet dashboard. More content will be added later.</p>

        <Link to="/dashboard/features">
          <button className="primary-btn">
            View Feature Analysis
          </button>
        </Link>
      </div>

      {loading && <LoadingSpinner />}
      {error && <p className="error-text">{error}</p>}

      {!loading && !error && isEmptyStats && (
        <p className="muted-text">
          No dashboard statistics available yet.
        </p>
      )}

      {!loading && !error && stats && !isEmptyStats && (
        <div className="metrics-section">
          <MetricCard title="Total Events" value={stats.totalEvents} />
          <MetricCard title="Unique IPs" value={stats.uniqueIPs} />
          <MetricCard title="Active Honeypots" value={stats.activeHoneypots} />
          <MetricCard title="Avg Threat Score" value={`${stats.avgThreatScore}%`} />
          <MetricCard title="Critical Alerts" value={stats.criticalAlerts} />

          {/* ✅ FIXED FEATURE ANALYSIS SLOT */}
          <div className={`feature-analysis-card ${theme}`}>
            <h3>Feature Analysis</h3>
            <p>Inspect extracted ML features for network events.</p>

            <Link to="/dashboard/features">
              <button className="secondary-btn">
                Open
              </button>
            </Link>
          </div>
        </div>
      )}

      <div style={{ marginTop: "40px" }}>
        <HoneypotStatus />
      </div>

      <div style={{ marginTop: "40px" }}>
        <NetworkVisualization />
      </div>
    </div>
  );
};

export default Dashboard;

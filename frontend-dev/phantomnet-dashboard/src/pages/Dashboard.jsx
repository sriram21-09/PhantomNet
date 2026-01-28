/**
 * Dashboard Page
 * --------------
 * Main overview page showing metrics, honeypot status,
 * and network visualization.
 */
import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import MetricCard from "../components/MetricCard";
import LoadingSpinner from "../components/LoadingSpinner";
import HoneypotStatus from "../components/Honeypotstatus";
import NetworkVisualization from "../components/NetworkVisualization";

const Dashboard = () => {
  // Week 2 – Day 2 to Day 6
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
        if (!response.ok) {
          throw new Error("Failed to fetch dashboard stats");
        }

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
    <div className="page-container dashboard-container">
      {/* =========================
         DASHBOARD HEADER
      ========================== */}
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <p>This is the PhantomNet dashboard. More content will be added later.</p>

        {/* ✅ VIEW FEATURE ANALYSIS BUTTON */}
        <Link to="/dashboard/features">
          <button
            style={{
              marginTop: "15px",
              padding: "10px 18px",
              backgroundColor: "#2563eb",
              color: "white",
              border: "none",
              borderRadius: "6px",
              cursor: "pointer",
            }}
          >
            View Feature Analysis
          </button>
        </Link>
      </div>

      {/* =========================
         LOADING / ERROR / EMPTY
      ========================== */}
      {loading && <LoadingSpinner />}

      {error && <p style={{ color: "red" }}>{error}</p>}

      {!loading && !error && isEmptyStats && (
        <p style={{ marginTop: "20px", color: "#666" }}>
          No dashboard statistics available yet.
        </p>
      )}

      {/* =========================
         METRICS SECTION
      ========================== */}
      {!loading && !error && stats && !isEmptyStats && (
        <div
          className="metrics-section"
          style={{
            display: "flex",
            gap: "20px",
            marginTop: "20px",
            flexWrap: "wrap",
          }}
        >
          <MetricCard title="Total Events" value={stats.totalEvents} color="#e3f2fd" />
          <MetricCard title="Unique IPs" value={stats.uniqueIPs} color="#e8f5e9" />
          <MetricCard title="Active Honeypots" value={stats.activeHoneypots} color="#ffeee2" />
          <MetricCard
            title="Avg Threat Score"
            value={`${stats.avgThreatScore}%`}
            color="#fff3e0"
          />
          <MetricCard title="Critical Alerts" value={stats.criticalAlerts} color="#ffebee" />

          {/* ✅ FEATURE ANALYSIS CARD */}
          <div
            style={{
              background: "white",
              padding: "20px",
              borderRadius: "10px",
              boxShadow: "0 4px 10px rgba(0,0,0,0.1)",
              minWidth: "220px",
            }}
          >
            <h3>Feature Analysis</h3>
            <p style={{ fontSize: "14px", color: "#555" }}>
              Inspect extracted ML features for network events.
            </p>

            <Link to="/dashboard/features">
              <button
                style={{
                  marginTop: "10px",
                  padding: "8px 14px",
                  backgroundColor: "#1e40af",
                  color: "white",
                  border: "none",
                  borderRadius: "6px",
                  cursor: "pointer",
                }}
              >
                Open
              </button>
            </Link>
          </div>
        </div>
      )}

      {/* =========================
         WEEK 5 – DAY 2
      ========================== */}
      <div style={{ marginTop: "40px" }}>
        <HoneypotStatus />
      </div>

      {/* =========================
         WEEK 5 – DAY 3
      ========================== */}
      <div style={{ marginTop: "40px" }}>
        <NetworkVisualization />
      </div>

      {/* =========================
         FUTURE SECTIONS
      ========================== */}
      <div className="charts-section" style={{ marginTop: "40px" }}>
        {/* Charts in future */}
      </div>

      <div className="table-section" style={{ marginTop: "40px" }}>
        {/* Tables in future */}
      </div>
    </div>
  );
};

export default Dashboard;

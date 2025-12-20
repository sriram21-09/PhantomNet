import React, { useEffect, useState } from "react";
import MetricCard from "../components/MetricCard";
import LoadingSpinner from "../components/LoadingSpinner";

const Dashboard = () => {
  // Week 2 – Day 2 to Day 6
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

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

        // ✅ Safety defaults (Day-3 & Day-6)
        setStats({
          totalEvents: data.totalEvents ?? 0,
          uniqueIPs: data.uniqueIPs ?? 0,
          activeHoneypots: data.activeHoneypots ?? 0,
          avgThreatScore: data.avgThreatScore ?? 0,
          criticalAlerts: data.criticalAlerts ?? 0
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

  return (
    <div style={{ padding: "20px" }}>
      <h1>Dashboard</h1>
      <p>This is the PhantomNet dashboard. More content will be added later.</p>

      {/* ✅ Loading Spinner */}
      {loading && <LoadingSpinner />}

      {/* ✅ Error State */}
      {error && <p style={{ color: "red" }}>{error}</p>}

      {/* ✅ Empty State (Day-6) */}
      {!loading && !error && isEmptyStats && (
        <p style={{ marginTop: "20px", color: "#666" }}>
          No dashboard statistics available yet.
        </p>
      )}

      {/* ✅ Stat Cards */}
      {!loading && !error && stats && !isEmptyStats && (
        <div
          style={{
            display: "flex",
            gap: "20px",
            marginTop: "20px",
            flexWrap: "wrap"
          }}
        >
          <MetricCard
            title="Total Events"
            value={stats.totalEvents}
            color="#e3f2fd"
          />

          <MetricCard
            title="Unique IPs"
            value={stats.uniqueIPs}
            color="#e8f5e9"
          />

          <MetricCard
            title="Active Honeypots"
            value={stats.activeHoneypots}
            color="#ffeee2"
          />

          <MetricCard
            title="Avg Threat Score"
            value={`${stats.avgThreatScore}%`}
            color="#fff3e0"
          />

          <MetricCard
            title="Critical Alerts"
            value={stats.criticalAlerts}
            color="#ffebee"
          />
        </div>
      )}
    </div>
  );
};

export default Dashboard;
import React, { useEffect, useState } from "react";
import MetricCard from "../components/MetricCard";

const Dashboard = () => {
  // Week 2 – Day 2 & Day 3: API driven stats
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

        // ✅ Safety defaults (important for Day-3)
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

  return (
    <div style={{ padding: "20px" }}>
      <h1>Dashboard</h1>
      <p>This is the PhantomNet dashboard. More content will be added later.</p>

      {loading && <p>Loading dashboard stats...</p>}
      {error && <p style={{ color: "red" }}>{error}</p>}

      {/* ✅ Step-7: All stat cards including Critical Alerts */}
      {stats && (
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

          {/* ⭐ Step-7 */}
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
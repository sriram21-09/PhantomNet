import React from "react";
import MetricCard from "../components/MetricCard";

const Dashboard = () => {
  /**
   * Week 2 – Day 1
   * Temporary static stats (will be replaced by API in Day 2)
   */
  const stats = {
    totalEvents: 24,
    uniqueIPs: 23,
    activeHoneypots: 7,
    avgThreatScore: 62
  };

  return (
    <div style={{ padding: "20px" }}>
      <h1>Dashboard</h1>
      <p>This is the PhantomNet dashboard. More content will be added later.</p>

      {/* Metric Cards */}
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
      </div>
    </div>
  );
};

export default Dashboard;
import React from "react";
import MetricCard from "../components/MetricCard";
import mockEvents from "../data/mockEvents.json";

function Dashboard() {
  // 🔢 Calculate metrics from JSON data
  const totalEvents = mockEvents.length;

  const uniqueIPs = new Set(
    mockEvents.map((event) => event.source_ip)
  ).size;

  const activeHoneypots = new Set(
    mockEvents.map((event) => event.honeypot_type)
  ).size;

  return (
    <div className="dashboard">
      <h1>Dashboard</h1>
      <p>This is the PhantomNet dashboard. More content will be added later.</p>

      <div className="metrics-grid">
        <MetricCard
          title="Total Events"
          value={totalEvents}
          icon="📈"
          accent="blue"
        />
        <MetricCard
          title="Unique IPs"
          value={uniqueIPs}
          icon="🌐"
          accent="green"
        />
        <MetricCard
          title="Active Honeypots"
          value={activeHoneypots}
          icon="🧪"
          accent="red"
        />
      </div>
    </div>
  );
}

export default Dashboard;
import React from "react";
import MetricCard from "../components/MetricCard";
import mockEvents from "../data/mockEvents.json";

function Dashboard() {
  const totalEvents = mockEvents.length;
  const uniqueIPs = new Set(mockEvents.map((event) => event.source_ip)).size;
  const activeHoneypots = new Set(
    mockEvents.map((event) => event.honeypot_type)
  ).size;

  return (
    <div className="page dashboard">
      <h1>Dashboard</h1>
      <p>This is the PhantomNet dashboard. More content will be added later.</p>

      <div className="metrics-grid">
        <MetricCard
          title="Total Events"
          value={totalEvents}
          accent="blue"
        />
        <MetricCard
          title="Unique IPs"
          value={uniqueIPs}
          accent="green"
        />
        <MetricCard
          title="Active Honeypots"
          value={activeHoneypots}
          accent="red"
        />
      </div>
    </div>
  );
}

export default Dashboard;
// src/pages/Dashboard.jsx
import MetricCard from "../components/MetricCard";

function Dashboard() {
  // Placeholder values for Day 3
  const totalEvents = 1234;
  const uniqueIPs = 89;
  const activeHoneypots = 2;

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
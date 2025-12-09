// src/pages/Dashboard.jsx
import MetricCard from "../components/MetricCard";

function Dashboard() {
  return (
    <div className="dashboard">
      <h1>Dashboard</h1>
      <p>This is the PhantomNet dashboard. More content will be added later.</p>

      <div className="metrics-grid">
        <MetricCard title="Total Events" value={1234} icon="📊" />
        <MetricCard title="Unique IPs" value={89} icon="🌐" />
        <MetricCard title="Active Honeypots" value={2} icon="🍯" />
      </div>
    </div>
  );
}

export default Dashboard;
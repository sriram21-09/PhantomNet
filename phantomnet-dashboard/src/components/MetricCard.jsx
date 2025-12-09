// src/components/MetricCard.jsx

// MetricCard receives 3 props: title, value, icon
function MetricCard({ title, value, icon }) {
  return (
    <div className="metric-card">
      <div className="metric-icon">{icon}</div>
      <div className="metric-title">{title}</div>
      <div className="metric-value">{value}</div>
    </div>
  );
}

export default MetricCard;
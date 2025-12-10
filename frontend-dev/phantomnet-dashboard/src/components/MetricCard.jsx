// src/components/MetricCard.jsx

function MetricCard({ title, value, icon, accent = "blue" }) {
  return (
    <div className={`metric-card metric-card--${accent}`}>
      {icon && <div className="metric-icon">{icon}</div>}
      <div className="metric-title">{title}</div>
      <div className="metric-value">{value}</div>
    </div>
  );
}

export default MetricCard;
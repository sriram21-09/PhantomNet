// src/components/MetricCard.jsx

const MetricCard = ({
  title = "Metric",
  value = "--",
  icon = null
}) => {
  return (
    <div className="metric-card card">
      {/* Optional Icon */}
      {icon && <div className="metric-icon">{icon}</div>}

      <h3 className="metric-title">{title}</h3>
      <h2 className="metric-value">{value}</h2>
    </div>
  );
};

export default MetricCard;
const MetricCard = ({ title, value, variant = "blue" }) => {
  return (
    <div className={`metric-card metric-${variant}`}>
      <p className="metric-title">{title}</p>
      <h2 className="metric-value">{value}</h2>
    </div>
  );
};

export default MetricCard;

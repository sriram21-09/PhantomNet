// src/components/MetricCard.jsx

const MetricCard = ({ title = "Metric", value = "--", icon = null }) => {
  return (
    <div className="metric-card card">
      {/* Optional Icon */}
      {icon && (
        <div
          className="metric-icon"
          style={{
            marginBottom: "10px",
            color: "var(--primary)",
            fontSize: "1.2rem",
          }}
        >
          {icon}
        </div>
      )}

      {/* Metric title */}
      <h3
        className="metric-title"
        style={{
          fontSize: "0.85rem",
          fontWeight: "600",
          letterSpacing: "0.4px",
          color: "var(--muted-text)",
          marginBottom: "6px",
          textTransform: "uppercase",
        }}
      >
        {title}
      </h3>

      {/* Metric value */}
      <h2
        className="metric-value"
        style={{
          fontSize: "2.1rem",
          fontWeight: "800",
          lineHeight: "1.1",
        }}
      >
        {value}
      </h2>
    </div>
  );
};

export default MetricCard;

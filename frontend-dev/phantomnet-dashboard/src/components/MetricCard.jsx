// src/components/MetricCard.jsx

const MetricCard = ({
  title = "Metric",
  value = "--",
  color = "#f5f5f5",
  icon = null
}) => {
  return (
    <div
      style={{
        backgroundColor: color,
        padding: "20px",
        borderRadius: "10px",
        minWidth: "180px",
        textAlign: "center",
        boxShadow: "0 2px 6px rgba(0,0,0,0.1)"
      }}
    >
      {/* Optional Icon (future use) */}
      {icon && (
        <div style={{ fontSize: "24px", marginBottom: "8px" }}>
          {icon}
        </div>
      )}

      <h3 style={{ margin: "0 0 8px 0" }}>{title}</h3>
      <h2 style={{ margin: 0 }}>{value}</h2>
    </div>
  );
};

export default MetricCard;

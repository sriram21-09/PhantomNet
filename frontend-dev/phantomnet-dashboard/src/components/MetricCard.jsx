const MetricCard = ({ title, value, color }) => {
  return (
    <div
      style={{
        background: color,
        padding: "20px",
        borderRadius: "10px",
        minWidth: "180px",
        textAlign: "center",
        boxShadow: "0 2px 6px rgba(0,0,0,0.1)"
      }}
    >
      <h3>{title}</h3>
      <h2>{value}</h2>
    </div>
  );
};

export default MetricCard;
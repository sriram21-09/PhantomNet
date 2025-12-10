function MetricCard({ title, value, color }) {
  const cardColors = {
    blue: "#e0edff",
    green: "#e6ffe6",
    red: "#ffe6e6"
  };

  return (
    <div className="metric-card" style={{ backgroundColor: cardColors[color] }}>
      <h3>{title}</h3>
      <p>{value}</p>
    </div>
  );
}

export default MetricCard;
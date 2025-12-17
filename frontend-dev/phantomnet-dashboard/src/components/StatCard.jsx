function StatCard({ title, value, color }) {
  return (
    <div
      style={{
        padding: "20px",
        borderRadius: "8px",
        backgroundColor: color,
        color: "#000",
        minWidth: "200px",
        textAlign: "center"
      }}
    >
      <h3>{title}</h3>
      <h2>{value}</h2>
    </div>
  );
}

export default StatCard;
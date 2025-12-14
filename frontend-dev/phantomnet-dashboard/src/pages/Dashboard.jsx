import mockEvents from "../data/mockEvents";

const Dashboard = () => {
  const totalEvents = mockEvents.length;
  const uniqueIPs = new Set(mockEvents.map(e => e.ip)).size;
  const activeHoneypots = new Set(mockEvents.map(e => e.type)).size;

  return (
    <div style={{ padding: "30px" }}>
      <h1>Dashboard</h1>
      <p>This is the PhantomNet dashboard. More content will be added later.</p>

      <div style={{ display: "flex", gap: "20px", marginTop: "20px" }}>
        <Card title="Total Events" value={totalEvents} color="#e0f2fe" />
        <Card title="Unique IPs" value={uniqueIPs} color="#dcfce7" />
        <Card title="Active Honeypots" value={activeHoneypots} color="#fee2e2" />
      </div>
    </div>
  );
};

const Card = ({ title, value, color }) => (
  <div style={{
    background: color,
    padding: "20px",
    borderRadius: "10px",
    minWidth: "180px",
    textAlign: "center"
  }}>
    <h3>{title}</h3>
    <h2>{value}</h2>
  </div>
);

export default Dashboard;
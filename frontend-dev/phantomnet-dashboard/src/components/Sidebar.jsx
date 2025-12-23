import { Link } from "react-router-dom";

const Sidebar = () => {
  return (
    <div style={{
      width: "200px",
      background: "#1e3a8a",
      color: "white",
      padding: "20px",
      height: "100vh"
    }}>
      <h2>PhantomNet</h2>
      <nav>
        <p><Link to="/dashboard" style={{ color: "white" }}>Dashboard</Link></p>
        <p><Link to="/events" style={{ color: "white" }}>Events</Link></p>
        <p><Link to="/honeypots" style={{ color: "white" }}>Honeypots</Link></p>
      </nav>
    </div>
  );
};

export default Sidebar;
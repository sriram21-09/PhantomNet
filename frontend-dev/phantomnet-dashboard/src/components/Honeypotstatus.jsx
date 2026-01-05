import { useEffect, useState } from "react";
import "../styles/honeypot.css";

/* =========================
   MOCK DATA (BACKEND SAFE)
========================= */
const mockHoneypots = [
  { name: "SSH", port: 22, status: "active", lastSeen: "2025-01-10 10:30" },
  { name: "HTTP", port: 80, status: "active", lastSeen: "2025-01-10 10:28" },
  { name: "FTP", port: 21, status: "inactive", lastSeen: "2025-01-10 09:55" },
  { name: "SMTP", port: 25, status: "active", lastSeen: "2025-01-10 10:25" }
];

const HoneypotStatus = () => {
  const [honeypots, setHoneypots] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  /* =========================
     FETCH / REFRESH DATA
  ========================== */
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        setLoading(true);

        // 🔴 Backend placeholder (future use)
        // const res = await fetch("/api/honeypots/status");
        // const data = await res.json();

        // ✅ Using mock data for now
        setHoneypots(mockHoneypots);
        setError(null);
      } catch (err) {
        console.error("Honeypot status error:", err);
        setError("Failed to load honeypot status");
      } finally {
        setLoading(false);
      }
    };

    fetchStatus();

    // 🔁 Auto-refresh every 5 seconds
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  /* =========================
     UI
  ========================== */
  return (
    <div className="honeypot-container">
      <h2>Honeypot Status</h2>

      {loading && <p>Loading honeypot status...</p>}
      {error && <p className="error">{error}</p>}

      <div className="honeypot-grid">
        {honeypots.map((hp, index) => (
          <div
            key={index}
            className={`honeypot-card ${
              hp.status === "active" ? "active" : "inactive"
            }`}
          >
            <h3>{hp.name}</h3>
            <p>Port: {hp.port}</p>
            <p>Status: {hp.status}</p>
            <p>Last Seen: {hp.lastSeen}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default HoneypotStatus;
import { useEffect, useState } from "react";
import "../styles/honeypot.css";

/**
 * HoneypotStatus Component
 * ------------------------
 * Displays real-time honeypot status from backend.
 * - Backend is the single source of truth
 * - Auto-refreshes every 5 seconds
 */

const HoneypotStatus = () => {
  const [honeypots, setHoneypots] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchHoneypots = async () => {
    try {
      setLoading(true);
      setError(null);

      const res = await fetch("http://127.0.0.1:8000/api/honeypots");

      if (!res.ok) {
        throw new Error(`Backend error: ${res.status}`);
      }

      const data = await res.json();
      setHoneypots(data);
    } catch (err) {
      console.error("Failed to fetch honeypot status:", err);
      setError("Honeypot service unavailable");
      setHoneypots([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHoneypots();

    // Auto-refresh every 5 seconds
    const interval = setInterval(fetchHoneypots, 5000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="section">
      <h2>Honeypot Status</h2>

      {loading && <p>Loading honeypot status...</p>}

      {error && <p className="error">{error}</p>}

      {!loading && !error && honeypots.length === 0 && (
        <p>No honeypot data available.</p>
      )}

      <div className="honeypot-grid">
        {honeypots.map((hp) => (
          <div
            key={hp.name}
            className={`honeypot-card ${
              hp.status === "active" ? "active" : "inactive"
            }`}
          >
            <h3>{hp.name}</h3>
            <p>Port: {hp.port}</p>
            <p>Status: {hp.status}</p>
            <p>Last Seen: {hp.last_seen ?? "N/A"}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default HoneypotStatus;

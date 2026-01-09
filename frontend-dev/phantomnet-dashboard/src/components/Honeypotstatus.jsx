/**
 * HoneypotStatus Component
 * ------------------------
 * Displays the current status of honeypots.
 * - Fetches data from backend API
 * - Falls back to mock data if backend is unavailable
 * - Auto-refreshes every 5 seconds
 */
import { useEffect, useState } from "react";
import "../styles/honeypot.css";

/* =========================
   MOCK DATA (FALLBACK ONLY)
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
     FETCH DATA
  ========================== */
  useEffect(() => {
    let isMounted = true;

    const fetchStatus = async () => {
      try {
        setLoading(true);
        setError(null);

        // ✅ REAL API (PRIMARY)
        const res = await fetch("http://127.0.0.1:8000/api/honeypots/status");

        if (!res.ok) {
          throw new Error("Backend error");
        }

        const data = await res.json();
        if (isMounted) {
          setHoneypots(data);
        }
      } catch (error) {
  console.warn("Backend unavailable. Using mock data.", error);

        if (isMounted) {
          setHoneypots(mockHoneypots);
          setError("Backend unavailable. Showing mock data.");
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    fetchStatus();

    // 🔁 Auto-refresh every 5 seconds
    const interval = setInterval(fetchStatus, 5000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
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
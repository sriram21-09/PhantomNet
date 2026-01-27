import { useEffect, useState } from "react";

const HoneypotStatus = () => {
  const [honeypots, setHoneypots] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchHoneypots = async () => {
      try {
        setLoading(true);
        setError(null);

        const res = await fetch("http://127.0.0.1:8000/api/honeypots");

        if (!res.ok) {
          throw new Error("Failed to fetch honeypot status");
        }

        const data = await res.json();
        setHoneypots(data); // ✅ backend data
      } catch {
        // ✅ removed unused err
        setError("Backend unavailable");
        setHoneypots([]);
      } finally {
        setLoading(false);
      }
    };

    fetchHoneypots();
  }, []);

  return (
    <div className="section">
      <h2>Honeypot Status</h2>

      {loading && <p>Loading honeypot status...</p>}
      {error && <p className="error">{error}</p>}

      <div className="honeypot-grid">
        {honeypots.map((hp, index) => (
          <div
            key={index}
            className={`card ${hp.status === "active" ? "active" : "inactive"}`}
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
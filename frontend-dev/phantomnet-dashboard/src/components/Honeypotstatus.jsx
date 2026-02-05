import { useEffect, useState } from "react";
import "../styles/honeypot.css";

const HoneypotStatus = () => {
  const [honeypots, setHoneypots] = useState([]);
  const [error, setError] = useState(null);

  const fetchHoneypots = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/honeypots");
      if (!res.ok) throw new Error();
      setHoneypots(await res.json());
    } catch {
      setError("Honeypot service unavailable");
    }
  };

  useEffect(() => {
    fetchHoneypots();
    const i = setInterval(fetchHoneypots, 5000);
    return () => clearInterval(i);
  }, []);

  return (
    <div className="honeypot-section">
      <h2>Honeypot Status</h2>
      {error && <p className="error-text">{error}</p>}

      <div className="honeypot-grid">
        {honeypots.map(hp => (
          <div key={hp.name} className={`honeypot-card ${hp.status}`}>
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

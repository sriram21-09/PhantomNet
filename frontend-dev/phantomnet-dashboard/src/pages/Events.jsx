import { useEffect, useState } from "react";
import "./events.css";

const Events = () => {

  /* =========================
     STEP 1: STATES
  ========================== */
  const [allEvents, setAllEvents] = useState([]);
  const [events, setEvents] = useState([]);

  const [search, setSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("ALL");
  const [threatFilter, setThreatFilter] = useState("ALL");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  /* =========================
     STEP 2: FETCH EVENTS
  ========================== */
  useEffect(() => {
    const fetchEvents = async () => {
      try {
        setLoading(true);
        setError(null);

        const res = await fetch("http://localhost:3000/api/events");
        if (!res.ok) throw new Error("Failed to fetch events");

        const data = await res.json();

        setAllEvents(data);
        setEvents(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchEvents();
  }, []);

  /* =========================
     STEP 3: THREAT LEVEL LOGIC
  ========================== */
  const getThreatLevel = (event) => {
    if (event.port === 23 || event.port === 3389) return "CRITICAL";
    if (event.type === "SSH" || event.type === "FTP") return "SUSPICIOUS";
    return "SAFE";
  };

  /* =========================
     STEP 4 & 5: APPLY FILTERS
  ========================== */
  useEffect(() => {
    let filtered = [...allEvents];

    // Protocol filter
    if (protocolFilter !== "ALL") {
      filtered = filtered.filter(
        (e) => e.type === protocolFilter
      );
    }

    // Threat filter (derived)
    if (threatFilter !== "ALL") {
      filtered = filtered.filter(
        (e) => getThreatLevel(e) === threatFilter
      );
    }

    // Search by IP or details
    if (search.trim() !== "") {
      filtered = filtered.filter(
        (e) =>
          e.ip.toLowerCase().includes(search.toLowerCase()) ||
          e.details.toLowerCase().includes(search.toLowerCase())
      );
    }

    setEvents(filtered);
  }, [search, protocolFilter, threatFilter, allEvents]);

  /* =========================
     UI
  ========================== */
  return (
    <div className="events-container">
      <h1>Events</h1>

      {/* Filters */}
      <div className="controls">
        <input
          type="text"
          placeholder="Search by IP or details"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />

        <select
          value={protocolFilter}
          onChange={(e) => setProtocolFilter(e.target.value)}
        >
          <option value="ALL">All Protocols</option>
          <option value="HTTP">HTTP</option>
          <option value="SSH">SSH</option>
          <option value="FTP">FTP</option>
          <option value="TELNET">TELNET</option>
        </select>

        <select
          value={threatFilter}
          onChange={(e) => setThreatFilter(e.target.value)}
        >
          <option value="ALL">All Threats</option>
          <option value="SAFE">Safe</option>
          <option value="SUSPICIOUS">Suspicious</option>
          <option value="CRITICAL">Critical</option>
        </select>
      </div>

      {/* Loading / Error */}
      {loading && <p>Loading events...</p>}
      {error && <p className="error">{error}</p>}

      {/* Table */}
      {!loading && !error && (
        <table className="events-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Protocol</th>
              <th>Port</th>
              <th>Threat</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event, index) => (
              <tr key={index}>
                <td>{event.time}</td>
                <td>{event.ip}</td>
                <td>{event.type}</td>
                <td>{event.port}</td>
                <td className={getThreatLevel(event).toLowerCase()}>
                  {getThreatLevel(event)}
                </td>
                <td>{event.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default Events;
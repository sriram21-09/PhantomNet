import { useEffect, useState } from "react";
import LoadingSpinner from "../components/LoadingSpinner";
import "./events.css";

const Events = () => {
  /* =========================
     STATE MANAGEMENT
     (Week 2 logic – unchanged)
  ========================== */
  const [allEvents, setAllEvents] = useState([]);
  const [events, setEvents] = useState([]);

  const [search, setSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("ALL");
  const [threatFilter, setThreatFilter] = useState("ALL");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  /* =========================
     FETCH EVENTS
  ========================== */
  useEffect(() => {
    const fetchEvents = async () => {
      try {
        setLoading(true);
        setError(null);

        const res = await fetch("http://localhost:3000/api/events");
        if (!res.ok) throw new Error("Failed to fetch events");

        const data = await res.json();
        setAllEventsControlled(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchEvents();
  }, []);

  const setAllEventsControlled = (data) => {
    setAllEvents(data);
    setEvents(data);
  };

  /* =========================
     THREAT LOGIC
  ========================== */
  const getThreatLevel = (event) => {
    if (event.port === 23 || event.port === 3389) return "CRITICAL";
    if (event.type === "SSH" || event.type === "FTP") return "SUSPICIOUS";
    return "SAFE";
  };

  const getThreatStyle = (level) => {
    switch (level) {
      case "CRITICAL":
        return { backgroundColor: "#fdecea", color: "#d32f2f" };
      case "SUSPICIOUS":
        return { backgroundColor: "#fff4e5", color: "#f57c00" };
      case "SAFE":
        return { backgroundColor: "#e8f5e9", color: "#388e3c" };
      default:
        return {};
    }
  };

  /* =========================
     APPLY FILTERS
  ========================== */
  useEffect(() => {
    let filtered = [...allEvents];

    if (protocolFilter !== "ALL") {
      filtered = filtered.filter((e) => e.type === protocolFilter);
    }

    if (threatFilter !== "ALL") {
      filtered = filtered.filter(
        (e) => getThreatLevel(e) === threatFilter
      );
    }

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
     THREAT SUMMARY
  ========================== */
  const threatSummary = {
    SAFE: events.filter((e) => getThreatLevel(e) === "SAFE").length,
    SUSPICIOUS: events.filter((e) => getThreatLevel(e) === "SUSPICIOUS").length,
    CRITICAL: events.filter((e) => getThreatLevel(e) === "CRITICAL").length
  };

  /* =========================
     PAGE UI (Week 3 – Day 1)
  ========================== */
  return (
    <div className="events-container">
      {/* ======================
         PAGE HEADER
      ====================== */}
      <div className="events-header">
        <h1>Events</h1>
      </div>

      {/* ======================
         THREAT SUMMARY SECTION
         (Future component: ThreatSummary)
      ====================== */}
      <div className="threat-summary" style={{ display: "flex", gap: "20px", marginBottom: "15px" }}>
        <span style={{ color: "#388e3c" }}>🟢 Safe: {threatSummary.SAFE}</span>
        <span style={{ color: "#f57c00" }}>🟠 Suspicious: {threatSummary.SUSPICIOUS}</span>
        <span style={{ color: "#d32f2f" }}>🔴 Critical: {threatSummary.CRITICAL}</span>
      </div>

      {/* ======================
         FILTER CONTROLS
         (Future component: EventsFilters)
      ====================== */}
      <div className="controls">
        <input
          type="text"
          placeholder="Search by IP or details"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />

        <select value={protocolFilter} onChange={(e) => setProtocolFilter(e.target.value)}>
          <option value="ALL">All Protocols</option>
          <option value="HTTP">HTTP</option>
          <option value="SSH">SSH</option>
          <option value="FTP">FTP</option>
          <option value="TELNET">TELNET</option>
        </select>

        <select value={threatFilter} onChange={(e) => setThreatFilter(e.target.value)}>
          <option value="ALL">All Threats</option>
          <option value="SAFE">Safe</option>
          <option value="SUSPICIOUS">Suspicious</option>
          <option value="CRITICAL">Critical</option>
        </select>
      </div>

      {/* ======================
         STATES
      ====================== */}
      {loading && <LoadingSpinner />}

      {error && <p className="error">{error}</p>}

      {!loading && !error && events.length === 0 && (
        <p style={{ marginTop: "20px", color: "#666" }}>
          No events found for the selected filters.
        </p>
      )}

      {/* ======================
         EVENTS TABLE
         (Future component: EventsTable)
      ====================== */}
      {!loading && !error && events.length > 0 && (
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
            {events.map((event, index) => {
              const threat = getThreatLevel(event);
              return (
                <tr key={index}>
                  <td>{event.time}</td>
                  <td>{event.ip}</td>
                  <td>{event.type}</td>
                  <td>{event.port}</td>
                  <td>
                    <span
                      style={{
                        ...getThreatStyle(threat),
                        padding: "4px 10px",
                        borderRadius: "12px",
                        fontSize: "12px",
                        fontWeight: "bold"
                      }}
                    >
                      {threat}
                    </span>
                  </td>
                  <td>{event.details}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default Events;
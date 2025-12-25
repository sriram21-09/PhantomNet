import { useEffect, useState } from "react";
import LoadingSpinner from "../components/LoadingSpinner";
import "./events.css";

const Events = () => {
  /* =========================
     STEP 1: STATE MANAGEMENT
  ========================== */
  const [allEvents, setAllEvents] = useState([]);
  const [events, setEvents] = useState([]);

  const [search, setSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("ALL");
  const [threatFilter, setThreatFilter] = useState("ALL");

  // ✅ Week 3 Day 2
  const [sortBy, setSortBy] = useState("time");
  const [currentPage, setCurrentPage] = useState(1);

  const ITEMS_PER_PAGE = 5;

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

      // ✅ MOCK DATA (Week 3)
      const data = [
        {
          time: "2025-01-10 10:30",
          ip: "192.168.1.10",
          type: "SSH",
          port: 22,
          details: "SSH login attempt"
        },
        {
          time: "2025-01-10 11:00",
          ip: "10.0.0.5",
          type: "TELNET",
          port: 23,
          details: "Telnet connection detected"
        }
      ];

      setAllEvents(data);
      setEvents(data);
    } catch  {
      setError("Failed to load events");
    } finally {
      setLoading(false);
    }
  };

  fetchEvents();
}, []);

  /* =========================
     STEP 3: THREAT LOGIC
  ========================== */
  const getThreatLevel = (event) => {
    if (event.port === 23 || event.port === 3389) return "CRITICAL";
    if (event.type === "SSH" || event.type === "FTP") return "SUSPICIOUS";
    return "SAFE";
  };

  /* =========================
     STEP 4: THREAT STYLES
  ========================== */
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
     STEP 5: FILTER + SORT
  ========================== */
  useEffect(() => {
    let filtered = [...allEvents];

    if (protocolFilter !== "ALL") {
      filtered = filtered.filter(e => e.type === protocolFilter);
    }

    if (threatFilter !== "ALL") {
      filtered = filtered.filter(e => getThreatLevel(e) === threatFilter);
    }

    if (search.trim() !== "") {
      filtered = filtered.filter(
        e =>
          e.ip?.toLowerCase().includes(search.toLowerCase()) ||
          e.details?.toLowerCase().includes(search.toLowerCase())
      );
    }

    // ✅ Sorting (Week 3 Day 2)
    filtered.sort((a, b) => {
      if (sortBy === "port") return (b.port || 0) - (a.port || 0);
      return new Date(b.time) - new Date(a.time);
    });

    setEvents(filtered);
    setCurrentPage(1);
  }, [search, protocolFilter, threatFilter, sortBy, allEvents]);

  /* =========================
     STEP 6: PAGINATION
  ========================== */
  const totalPages = Math.ceil(events.length / ITEMS_PER_PAGE);
  const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
  const paginatedEvents = events.slice(
    startIndex,
    startIndex + ITEMS_PER_PAGE
  );

  /* =========================
     STEP 7: THREAT SUMMARY
  ========================== */
  const threatSummary = {
    SAFE: events.filter(e => getThreatLevel(e) === "SAFE").length,
    SUSPICIOUS: events.filter(e => getThreatLevel(e) === "SUSPICIOUS").length,
    CRITICAL: events.filter(e => getThreatLevel(e) === "CRITICAL").length
  };

  /* =========================
     UI
  ========================== */
  return (
    <div className="events-container">
      <h1>Events</h1>

      {/* THREAT SUMMARY */}
      <div style={{ display: "flex", gap: "20px", marginBottom: "15px" }}>
        <span style={{ color: "#388e3c" }}>🟢 Safe: {threatSummary.SAFE}</span>
        <span style={{ color: "#f57c00" }}>🟠 Suspicious: {threatSummary.SUSPICIOUS}</span>
        <span style={{ color: "#d32f2f" }}>🔴 Critical: {threatSummary.CRITICAL}</span>
      </div>

      {/* FILTERS */}
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

      {/* SORT */}
      <div style={{ marginBottom: "15px" }}>
        <label style={{ marginRight: "10px" }}>Sort By:</label>
        <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
          <option value="time">Latest First</option>
          <option value="port">Port</option>
        </select>
      </div>

      {/* STATES */}
      {loading && <LoadingSpinner />}
      {error && <p className="error">{error}</p>}

      {/* TABLE */}
      {!loading && !error && paginatedEvents.length > 0 && (
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
            {paginatedEvents.map((event, index) => {
              const threat = getThreatLevel(event);
              return (
                <tr key={index}>
                  <td>{event.time || "-"}</td>
                  <td>{event.ip || "-"}</td>
                  <td>{event.type || "-"}</td>
                  <td>{event.port || "-"}</td>
                  <td>
                    <span style={{
                      ...getThreatStyle(threat),
                      padding: "4px 10px",
                      borderRadius: "12px",
                      fontSize: "12px",
                      fontWeight: "bold"
                    }}>
                      {threat}
                    </span>
                  </td>
                  <td>{event.details || "-"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {/* PAGINATION */}
      {totalPages > 1 && (
        <div style={{ marginTop: "20px", textAlign: "center" }}>
          <button
            onClick={() => setCurrentPage(p => Math.max(p - 1, 1))}
            disabled={currentPage === 1}
          >
            Prev
          </button>

          <span style={{ margin: "0 15px" }}>
            Page {currentPage} of {totalPages}
          </span>

          <button
            onClick={() => setCurrentPage(p => Math.min(p + 1, totalPages))}
            disabled={currentPage === totalPages}
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
};

export default Events;
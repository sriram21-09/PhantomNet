import { useEffect, useState } from "react";
import LoadingSpinner from "../components/LoadingSpinner";
import "./events.css";

/* =========================
   MOCK FALLBACK DATA
========================= */
const mockEvents = [
  {
    time: "2025-01-10 10:30",
    ip: "192.168.1.10",
    type: "SSH",
    port: 22,
    threat: "SUSPICIOUS",
    details: "SSH login attempt"
  },
  {
    time: "2025-01-10 11:00",
    ip: "10.0.0.5",
    type: "TELNET",
    port: 23,
    threat: "MALICIOUS",
    details: "Telnet connection detected"
  }
];

const Events = () => {
  /* =========================
     STATE
  ========================== */
  const [allEvents, setAllEvents] = useState([]);
  const [events, setEvents] = useState([]);

  const [search, setSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("ALL");
  const [threatFilter, setThreatFilter] = useState("ALL");
  const [sortBy, setSortBy] = useState("time");

  const [currentPage, setCurrentPage] = useState(1);
  const ITEMS_PER_PAGE = 5;

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  /* =========================
     FETCH EVENTS (REAL API)
  ========================== */
  useEffect(() => {
    const fetchEvents = async () => {
      try {
        setLoading(true);
        setError(null);

        const res = await fetch("http://localhost:3000/api/events");
        if (!res.ok) throw new Error("API failed");

        const data = await res.json();
        setAllEvents(data);
        setEvents(data);
      } catch {
        setAllEvents(mockEvents);
        setEvents(mockEvents);
        setError("Failed to fetch API, showing mock data");
      } finally {
        setLoading(false);
      }
    };

    fetchEvents();
  }, []);

  /* =========================
     THREAT STYLING (NO LOGIC)
  ========================== */
  const getThreatStyle = (threat) => {
    switch (threat) {
      case "MALICIOUS":
        return { backgroundColor: "#fdecea", color: "#d32f2f" };
      case "SUSPICIOUS":
        return { backgroundColor: "#fff4e5", color: "#f57c00" };
      default:
        return { backgroundColor: "#e8f5e9", color: "#388e3c" };
    }
  };

  /* =========================
     FILTER + SORT
  ========================== */
  useEffect(() => {
    let filtered = [...allEvents];

    if (protocolFilter !== "ALL") {
      filtered = filtered.filter(e => e.type === protocolFilter);
    }

    if (threatFilter !== "ALL") {
      filtered = filtered.filter(e => e.threat === threatFilter);
    }

    if (search.trim()) {
      filtered = filtered.filter(
        e =>
          e.ip?.toLowerCase().includes(search.toLowerCase()) ||
          e.details?.toLowerCase().includes(search.toLowerCase())
      );
    }

    filtered.sort((a, b) => {
      if (sortBy === "port") return (b.port || 0) - (a.port || 0);
      return new Date(b.time) - new Date(a.time);
    });

    setEvents(filtered);
    setCurrentPage(1);
  }, [search, protocolFilter, threatFilter, sortBy, allEvents]);

  /* =========================
     PAGINATION
  ========================== */
  const totalPages = Math.ceil(events.length / ITEMS_PER_PAGE);
  const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
  const paginatedEvents = events.slice(startIndex, startIndex + ITEMS_PER_PAGE);

  /* =========================
     THREAT SUMMARY (BACKEND-TRUTH)
  ========================== */
  const threatSummary = {
    SAFE: events.filter(e => e.threat === "BENIGN").length,
    SUSPICIOUS: events.filter(e => e.threat === "SUSPICIOUS").length,
    CRITICAL: events.filter(e => e.threat === "MALICIOUS").length
  };

  /* =========================
     UI
  ========================== */
  return (
    <div className="page-container events-container">
      <h1>Events</h1>

      {/* SUMMARY */}
      <div style={{ display: "flex", gap: "20px", marginBottom: "15px" }}>
        <span>🟢 Safe: {threatSummary.SAFE}</span>
        <span>🟠 Suspicious: {threatSummary.SUSPICIOUS}</span>
        <span>🔴 Critical: {threatSummary.CRITICAL}</span>
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
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="ICMP">ICMP</option>
        </select>

        <select value={threatFilter} onChange={(e) => setThreatFilter(e.target.value)}>
          <option value="ALL">All Threats</option>
          <option value="BENIGN">Safe</option>
          <option value="SUSPICIOUS">Suspicious</option>
          <option value="MALICIOUS">Critical</option>
        </select>

        <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
          <option value="time">Latest First</option>
          <option value="port">Port</option>
        </select>
      </div>

      {/* STATES */}
      {loading && <LoadingSpinner />}
      {error && <p className="error">{error}</p>}

      {/* TABLE */}
      {!loading && paginatedEvents.length > 0 && (
        <table className="events-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>IP</th>
              <th>Protocol</th>
              <th>Port</th>
              <th>Threat</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {paginatedEvents.map((e, i) => (
              <tr key={i}>
                <td>{e.time}</td>
                <td>{e.ip}</td>
                <td>{e.type}</td>
                <td>{e.port}</td>
                <td>
                  <span
                    style={{
                      ...getThreatStyle(e.threat),
                      padding: "4px 10px",
                      borderRadius: "12px"
                    }}
                  >
                    {e.threat}
                  </span>
                </td>
                <td>{e.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* PAGINATION */}
      {totalPages > 1 && (
        <div style={{ marginTop: "20px", textAlign: "center" }}>
          <button onClick={() => setCurrentPage(p => Math.max(p - 1, 1))} disabled={currentPage === 1}>
            Prev
          </button>
          <span style={{ margin: "0 15px" }}>
            Page {currentPage} of {totalPages}
          </span>
          <button onClick={() => setCurrentPage(p => Math.min(p + 1, totalPages))} disabled={currentPage === totalPages}>
            Next
          </button>
        </div>
      )}
    </div>
  );
};

export default Events;
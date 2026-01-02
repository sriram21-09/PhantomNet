import { useEffect, useState } from "react";
import LoadingSpinner from "../components/LoadingSpinner";
import "./events.css";

/* =========================
   MOCK FALLBACK DATA
========================= */
const mockEvents = Array.from({ length: 100 }, (_, i) => ({
  time: `2025-01-10 10:${String(i).padStart(2, "0")}`,
  ip: `192.168.1.${i}`,
  type: i % 2 === 0 ? "SSH" : "TELNET",
  port: i % 2 === 0 ? 22 : 23,
  details: "Simulated attack event"
}));

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
     THREAT LOGIC (SINGLE SOURCE)
  ========================== */
  const getThreatLevel = (event) => {
    if (event.port === 23 || event.port === 3389) return "MALICIOUS";
    if (event.type === "SSH" || event.type === "FTP") return "SUSPICIOUS";
    return "BENIGN";
  };

  /* =========================
     FETCH EVENTS (API + FALLBACK)
  ========================== */
  useEffect(() => {
    const fetchEvents = async () => {
      try {
        setLoading(true);
        setError(null);

        const res = await fetch("http://localhost:3000/api/events");
        if (!res.ok) throw new Error("API failed");

        const data = await res.json();

        const normalized = data.map((e) => ({
          ...e,
          threat: getThreatLevel(e)
        }));

        setAllEvents(normalized);
        setEvents(normalized);
      } catch {
        const normalizedMock = mockEvents.map((e) => ({
          ...e,
          threat: getThreatLevel(e)
        }));

        setAllEvents(normalizedMock);
        setEvents(normalizedMock);
        setError("Failed to fetch API, showing mock data");
      } finally {
        setLoading(false);
      }
    };

    fetchEvents();
  }, []);

  /* =========================
     FILTER + SORT
  ========================== */
  useEffect(() => {
    let filtered = [...allEvents];

    if (protocolFilter !== "ALL") {
      filtered = filtered.filter((e) => e.type === protocolFilter);
    }

    if (threatFilter !== "ALL") {
      filtered = filtered.filter((e) => e.threat === threatFilter);
    }

    if (search.trim()) {
      filtered = filtered.filter(
        (e) =>
          e.ip.toLowerCase().includes(search.toLowerCase()) ||
          e.details.toLowerCase().includes(search.toLowerCase())
      );
    }

    filtered.sort((a, b) =>
      sortBy === "port"
        ? b.port - a.port
        : new Date(b.time) - new Date(a.time)
    );

    setEvents(filtered);
    setCurrentPage(1);
  }, [search, protocolFilter, threatFilter, sortBy, allEvents]);

  /* =========================
     PAGINATION
  ========================== */
  const totalPages = Math.ceil(events.length / ITEMS_PER_PAGE);
  const paginatedEvents = events.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE
  );

  /* =========================
     SUMMARY
  ========================== */
  const threatSummary = {
    SAFE: events.filter((e) => e.threat === "BENIGN").length,
    SUSPICIOUS: events.filter((e) => e.threat === "SUSPICIOUS").length,
    MALICIOUS: events.filter((e) => e.threat === "MALICIOUS").length
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
        <span>🔴 Malicious: {threatSummary.MALICIOUS}</span>
      </div>

      {/* FILTERS */}
      <div className="controls">
        <input
          placeholder="Search by IP or details"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />

        <select
          value={protocolFilter}
          onChange={(e) => setProtocolFilter(e.target.value)}
        >
          <option value="ALL">All Protocols</option>
          <option value="SSH">SSH</option>
          <option value="TELNET">TELNET</option>
          <option value="FTP">FTP</option>
        </select>

        <select
          value={threatFilter}
          onChange={(e) => setThreatFilter(e.target.value)}
        >
          <option value="ALL">All Threats</option>
          <option value="BENIGN">Safe</option>
          <option value="SUSPICIOUS">Suspicious</option>
          <option value="MALICIOUS">Malicious</option>
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
                <td>{e.threat}</td>
                <td>{e.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* PAGINATION */}
      {totalPages > 1 && (
        <div style={{ textAlign: "center", marginTop: "20px" }}>
          <button
            disabled={currentPage === 1}
            onClick={() => setCurrentPage((p) => p - 1)}
          >
            Prev
          </button>
          <span>
            {" "}
            Page {currentPage} of {totalPages}{" "}
          </span>
          <button
            disabled={currentPage === totalPages}
            onClick={() => setCurrentPage((p) => p + 1)}
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
};

export default Events;
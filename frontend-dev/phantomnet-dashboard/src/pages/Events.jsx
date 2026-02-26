import { useEffect, useState } from "react";
import {
  FaSearch,
  FaFilter,
  FaCheckCircle,
  FaExclamationTriangle,
  FaTimesCircle,
  FaChevronLeft,
  FaChevronRight,
  FaListAlt
} from "react-icons/fa";
import LoadingSpinner from "../components/LoadingSpinner";
import "../styles/pages/events.css";

const Events = () => {
  const [allEvents, setAllEvents] = useState([]);
  const [events, setEvents] = useState([]);
  const [search, setSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("ALL");
  const [threatFilter, setThreatFilter] = useState("ALL");
  const [sortBy, setSortBy] = useState("time");
  const [currentPage, setCurrentPage] = useState(1);
  const ITEMS_PER_PAGE = 10;
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        setLoading(true);
        setError(null);
        const res = await fetch("/api/events");
        if (!res.ok) throw new Error(`Backend API failed: ${res.status}`);
        const data = await res.json();
        setAllEvents(data);
        setEvents(data);
      } catch (err) {
        console.error("Failed to fetch /api/events:", err);
        setAllEvents([]);
        setEvents([]);
        setError("Backend unavailable. Cannot load events.");
      } finally {
        setLoading(false);
      }
    };
    fetchEvents();
  }, []);

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
      sortBy === "port" ? b.port - a.port : new Date(b.time) - new Date(a.time)
    );
    setEvents(filtered);
    setCurrentPage(1);
  }, [search, protocolFilter, threatFilter, sortBy, allEvents]);

  const totalPages = Math.ceil(events.length / ITEMS_PER_PAGE);
  const paginatedEvents = events.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE
  );

  const threatSummary = {
    SAFE: events.filter((e) => e.threat === "BENIGN").length,
    SUSPICIOUS: events.filter((e) => e.threat === "SUSPICIOUS").length,
    MALICIOUS: events.filter((e) => e.threat === "MALICIOUS").length
  };

  const getThreatBadge = (threat) => {
    const badges = {
      BENIGN: { class: "safe", icon: FaCheckCircle, label: "Safe" },
      SUSPICIOUS: { class: "warning", icon: FaExclamationTriangle, label: "Suspicious" },
      MALICIOUS: { class: "danger", icon: FaTimesCircle, label: "Malicious" }
    };
    const badge = badges[threat] || badges.BENIGN;
    const Icon = badge.icon;
    return (
      <span className={`threat-badge ${badge.class}`}>
        <Icon />
        {badge.label}
      </span>
    );
  };

  return (
    <div className="events-wrapper">
      {/* Header */}
      <div className="events-header">
        <div className="header-content">
          <div className="header-icon">
            <FaListAlt />
          </div>
          <div>
            <h1>Security Events</h1>
            <p>Real-time network activity monitoring and threat detection</p>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="events-summary">
        <div className="summary-card safe">
          <div className="summary-icon"><FaCheckCircle /></div>
          <div className="summary-info">
            <span className="summary-value">{threatSummary.SAFE}</span>
            <span className="summary-label">Safe Events</span>
          </div>
        </div>
        <div className="summary-card warning">
          <div className="summary-icon"><FaExclamationTriangle /></div>
          <div className="summary-info">
            <span className="summary-value">{threatSummary.SUSPICIOUS}</span>
            <span className="summary-label">Suspicious</span>
          </div>
        </div>
        <div className="summary-card danger">
          <div className="summary-icon"><FaTimesCircle /></div>
          <div className="summary-info">
            <span className="summary-value">{threatSummary.MALICIOUS}</span>
            <span className="summary-label">Malicious</span>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="events-filters">
        <div className="filter-group search">
          <FaSearch className="filter-icon" />
          <input
            placeholder="Search by IP or details..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="filter-group">
          <FaFilter className="filter-icon" />
          <select value={protocolFilter} onChange={(e) => setProtocolFilter(e.target.value)}>
            <option value="ALL">All Protocols</option>
            <option value="SSH">SSH</option>
            <option value="HTTP">HTTP</option>
            <option value="FTP">FTP</option>
            <option value="SMTP">SMTP</option>
          </select>
        </div>
        <div className="filter-group">
          <select value={threatFilter} onChange={(e) => setThreatFilter(e.target.value)}>
            <option value="ALL">All Threats</option>
            <option value="BENIGN">Safe</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="MALICIOUS">Malicious</option>
          </select>
        </div>
        <div className="filter-group">
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
            <option value="time">Latest First</option>
            <option value="port">By Port</option>
          </select>
        </div>
      </div>

      {/* Loading/Error States */}
      {loading && <LoadingSpinner />}
      {error && <div className="error-banner">{error}</div>}

      {/* Table */}
      {!loading && paginatedEvents.length > 0 && (
        <div className="events-table-wrapper">
          <table className="events-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Protocol</th>
                <th>Port</th>
                <th>Status</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {paginatedEvents.map((e, i) => (
                <tr key={i}>
                  <td className="time-cell">{e.time}</td>
                  <td className="ip-cell">{e.ip}</td>
                  <td><span className="protocol-badge">{e.type}</span></td>
                  <td>{e.port}</td>
                  <td>{getThreatBadge(e.threat)}</td>
                  <td className="details-cell">{e.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && events.length === 0 && (
        <div className="empty-state">
          <FaListAlt />
          <p>No events found</p>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="events-pagination">
          <button
            className="page-btn"
            disabled={currentPage === 1}
            onClick={() => setCurrentPage((p) => p - 1)}
          >
            <FaChevronLeft />
            Previous
          </button>
          <span className="page-info">
            Page <strong>{currentPage}</strong> of <strong>{totalPages}</strong>
          </span>
          <button
            className="page-btn"
            disabled={currentPage === totalPages}
            onClick={() => setCurrentPage((p) => p + 1)}
          >
            Next
            <FaChevronRight />
          </button>
        </div>
      )}
    </div>
  );
};

export default Events;
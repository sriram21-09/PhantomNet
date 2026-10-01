import { useEffect, useState, useCallback, useMemo } from "react";
import { Link } from "react-router-dom";
import {
  FaSearch,
  FaFilter,
  FaCheckCircle,
  FaExclamationTriangle,
  FaTimesCircle,
  FaChevronLeft,
  FaChevronRight,
  FaListAlt,
  FaSync,
  FaDatabase
} from "react-icons/fa";
import LoadingSpinner from "../components/LoadingSpinner";
import { useRealTime } from "../context/RealTimeContext";
import "../Styles/pages/events.css";

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
  const [dbSummary, setDbSummary] = useState(null);
  const [liveCount, setLiveCount] = useState(0);

  // Consume application-wide real-time WebSocket stream
  const { events: realtimeEvents, isConnected } = useRealTime();

  // Normalize any event item to authoritative schema
  const normalizeEvent = useCallback((item) => {
    const threatLevel = (item.threat_level || "LOW").toUpperCase();
    const isMal = Boolean(
      item.is_malicious ||
      threatLevel === "HIGH" ||
      threatLevel === "CRITICAL" ||
      item.threat === "MALICIOUS"
    );
    const isSusp = !isMal && (
      threatLevel === "MEDIUM" ||
      item.threat === "SUSPICIOUS" ||
      (item.threat_score >= 0.4 && item.threat_score < 0.8)
    );
    const threatCategory = isMal ? "MALICIOUS" : (isSusp ? "SUSPICIOUS" : "BENIGN");

    let displayTime = item.time;
    if (!displayTime && item.timestamp) {
      try {
        const dt = new Date(item.timestamp);
        displayTime = isNaN(dt.getTime()) ? String(item.timestamp) : dt.toISOString().replace("T", " ").slice(0, 19);
      } catch {
        displayTime = String(item.timestamp);
      }
    }

    const attackType = item.attack_type || (threatCategory === "BENIGN" ? "BENIGN" : "SUSPICIOUS");
    const decision = item.decision || (isMal ? "BLOCK" : (isSusp ? "ALERT" : "ALLOW"));
    const protocol = (item.protocol || item.type || "TCP").toUpperCase();

    return {
      id: item.id || `live-${Date.now()}-${Math.random()}`,
      time: displayTime || "Just now",
      timestamp: item.timestamp,
      ip: item.ip || item.src_ip || "Unknown",
      type: protocol,
      protocol: protocol,
      port: item.port !== undefined ? item.port : (item.dst_port !== undefined ? item.dst_port : 0),
      threat: threatCategory,
      threat_category: threatCategory,
      threat_level: threatLevel,
      attack_type: attackType,
      decision: decision,
      is_malicious: isMal,
      details: item.details || (threatCategory !== "BENIGN" ? `${attackType} activity detected (${decision})` : `Normal ${protocol} traffic`),
      isLive: Boolean(item.isLive)
    };
  }, []);

  // Fetch events with server-side filter support for authoritative results across the whole DB
  const fetchEvents = useCallback(async (proto = protocolFilter, threat = threatFilter) => {
    try {
      setLoading(true);
      setError(null);

      const params = new URLSearchParams({ limit: "500" });
      if (proto && proto !== "ALL") params.set("protocol", proto);
      if (threat && threat !== "ALL") params.set("threat", threat);

      // Parallel fetch: event logs + authoritative threat summary
      const [eventsRes, summaryRes] = await Promise.all([
        fetch(`/api/events?${params.toString()}`),
        fetch("/api/threats/summary").catch(() => null)
      ]);

      if (!eventsRes.ok) {
        if (eventsRes.status === 401) {
          throw new Error("Session expired or unauthenticated. Please log in.");
        }
        throw new Error(`Backend API failed: HTTP ${eventsRes.status}`);
      }

      const eventsData = await eventsRes.json();
      const normalized = (Array.isArray(eventsData) ? eventsData : []).map(normalizeEvent);
      setAllEvents(normalized);

      if (summaryRes && summaryRes.ok) {
        const summaryData = await summaryRes.json();
        setDbSummary(summaryData);
      }
    } catch (err) {
      setAllEvents([]);
      setEvents([]);
      setError(err.message || "Backend unavailable. Cannot load events.");
    } finally {
      setLoading(false);
    }
  }, [normalizeEvent, protocolFilter, threatFilter]);

  // Initial load
  useEffect(() => {
    fetchEvents(protocolFilter, threatFilter);
  }, []);

  // Handle Protocol filter change
  const handleProtocolChange = (val) => {
    setProtocolFilter(val);
    fetchEvents(val, threatFilter);
  };

  // Handle Threat filter change
  const handleThreatChange = (val) => {
    setThreatFilter(val);
    fetchEvents(protocolFilter, val);
  };

  // Reset all filters
  const handleResetFilters = () => {
    setSearch("");
    setProtocolFilter("ALL");
    setThreatFilter("ALL");
    setSortBy("time");
    fetchEvents("ALL", "ALL");
  };

  // Dynamically ingest incoming WebSocket events in real time
  useEffect(() => {
    if (!realtimeEvents || realtimeEvents.length === 0) return;

    setAllEvents((prev) => {
      const existingIds = new Set(prev.map((e) => String(e.id)));
      const incoming = realtimeEvents
        .filter((raw) => raw && !existingIds.has(String(raw.id || raw.event_id)))
        .map((raw) => normalizeEvent({ ...raw, isLive: true }))
        .filter((norm) => {
          if (protocolFilter !== "ALL" && norm.protocol !== protocolFilter && norm.type !== protocolFilter) return false;
          if (threatFilter === "MALICIOUS" && !norm.is_malicious && norm.threat !== "MALICIOUS") return false;
          if (threatFilter === "SUSPICIOUS" && (norm.is_malicious || norm.threat !== "SUSPICIOUS")) return false;
          if (threatFilter === "BENIGN" && (norm.is_malicious || norm.threat !== "BENIGN")) return false;
          return true;
        });

      if (incoming.length === 0) return prev;

      setLiveCount((c) => c + incoming.length);
      return [...incoming, ...prev].slice(0, 1000);
    });
  }, [realtimeEvents, normalizeEvent, protocolFilter, threatFilter]);

  // Client-side search and sorting
  useEffect(() => {
    let filtered = [...allEvents];

    if (search.trim()) {
      const q = search.toLowerCase();
      filtered = filtered.filter(
        (e) =>
          e.ip.toLowerCase().includes(q) ||
          e.details.toLowerCase().includes(q) ||
          (e.attack_type && e.attack_type.toLowerCase().includes(q)) ||
          e.protocol.toLowerCase().includes(q)
      );
    }

    filtered.sort((a, b) => {
      if (sortBy === "port") {
        return (b.port || 0) - (a.port || 0);
      }
      const timeA = new Date(a.time || a.timestamp).getTime();
      const timeB = new Date(b.time || b.timestamp).getTime();
      return (isNaN(timeB) ? 0 : timeB) - (isNaN(timeA) ? 0 : timeA);
    });

    setEvents(filtered);
    setCurrentPage(1);
  }, [search, sortBy, allEvents]);

  const totalPages = Math.max(1, Math.ceil(events.length / ITEMS_PER_PAGE));
  const paginatedEvents = events.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE
  );

  // Authoritative threat counts (prioritizing full DB summary when unfiltered)
  const isFiltered = protocolFilter !== "ALL" || threatFilter !== "ALL" || Boolean(search.trim());

  const threatSummary = useMemo(() => {
    if (!isFiltered && dbSummary) {
      return {
        SAFE: dbSummary.lowSeverity ?? 0,
        SUSPICIOUS: dbSummary.mediumSeverity ?? 0,
        MALICIOUS: dbSummary.highSeverity ?? 0
      };
    }
    return {
      SAFE: events.filter((e) => !e.is_malicious && e.threat === "BENIGN").length,
      SUSPICIOUS: events.filter((e) => !e.is_malicious && e.threat === "SUSPICIOUS").length,
      MALICIOUS: events.filter((e) => e.is_malicious || e.threat === "MALICIOUS").length
    };
  }, [isFiltered, dbSummary, events]);

  const getThreatBadge = (e) => {
    if (e.is_malicious || e.threat_level === "HIGH" || e.threat_level === "CRITICAL" || e.threat === "MALICIOUS") {
      return (
        <span className="threat-badge danger" title={e.attack_type || "Malicious attack"}>
          <FaTimesCircle />
          Malicious
        </span>
      );
    }
    if (e.threat_level === "MEDIUM" || e.threat === "SUSPICIOUS") {
      return (
        <span className="threat-badge warning" title={e.attack_type || "Suspicious traffic"}>
          <FaExclamationTriangle />
          Suspicious
        </span>
      );
    }
    return (
      <span className="threat-badge safe" title="Benign traffic">
        <FaCheckCircle />
        Safe
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
          <div className="header-text-block">
            <div className="title-row">
              <h1>Security Events</h1>
              <div className="live-status-pill" title={isConnected ? "Real-time WebSocket stream connected" : "Connecting to WebSocket"}>
                <span className={`pulse-dot ${isConnected ? "online" : "offline"}`} />
                <span className="live-status-text">
                  {isConnected ? "LIVE STREAM ACTIVE" : "CONNECTING..."}
                </span>
                {liveCount > 0 && <span className="live-badge">+{liveCount} new</span>}
              </div>
            </div>
            <p>Authoritative network activity monitoring, threat detection, and real-time event telemetry</p>
          </div>
          <div className="header-actions">
            <button
              id="refresh-btn"
              className="refresh-btn"
              onClick={() => fetchEvents(protocolFilter, threatFilter)}
              disabled={loading}
              title="Refresh security events"
              type="button"
            >
              <FaSync className={loading ? "spin-icon" : ""} />
              <span>Refresh</span>
            </button>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="events-summary">
        <div className="summary-card safe">
          <div className="summary-icon"><FaCheckCircle /></div>
          <div className="summary-info">
            <span className="summary-value">{threatSummary.SAFE}</span>
            <span className="summary-label">
              {isFiltered ? "Filtered Safe" : "Safe Events"}
            </span>
          </div>
        </div>
        <div className="summary-card warning">
          <div className="summary-icon"><FaExclamationTriangle /></div>
          <div className="summary-info">
            <span className="summary-value">{threatSummary.SUSPICIOUS}</span>
            <span className="summary-label">
              {isFiltered ? "Filtered Suspicious" : "Suspicious"}
            </span>
          </div>
        </div>
        <div className="summary-card danger">
          <div className="summary-icon"><FaTimesCircle /></div>
          <div className="summary-info">
            <span className="summary-value">{threatSummary.MALICIOUS}</span>
            <span className="summary-label">
              {isFiltered ? "Filtered Malicious" : "Malicious"}
            </span>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="events-filters">
        <div className="filter-group search">
          <FaSearch className="filter-icon" />
          <input
            id="search-input"
            aria-label="Search events"
            placeholder="Search by IP, details, attack type..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="filter-group">
          <FaFilter className="filter-icon" />
          <select
            id="protocol-filter"
            aria-label="Filter by Protocol"
            value={protocolFilter}
            onChange={(e) => handleProtocolChange(e.target.value)}
          >
            <option value="ALL">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="SSH">SSH</option>
            <option value="HTTP">HTTP</option>
            <option value="FTP">FTP</option>
            <option value="SMTP">SMTP</option>
          </select>
        </div>
        <div className="filter-group">
          <select
            id="threat-filter"
            aria-label="Filter by Threat Category"
            value={threatFilter}
            onChange={(e) => handleThreatChange(e.target.value)}
          >
            <option value="ALL">All Threats</option>
            <option value="BENIGN">Safe</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="MALICIOUS">Malicious</option>
          </select>
        </div>
        <div className="filter-group">
          <select
            id="sort-filter"
            aria-label="Sort by"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
          >
            <option value="time">Latest First</option>
            <option value="port">By Port</option>
          </select>
        </div>
      </div>

      {/* Loading/Error States */}
      {loading && <LoadingSpinner />}
      {error && (
        <div className="error-banner">
          <FaExclamationTriangle />
          <span>{error}</span>
          <button type="button" onClick={() => fetchEvents(protocolFilter, threatFilter)} className="retry-btn">Retry</button>
        </div>
      )}

      {/* Filter Stats Bar */}
      {!loading && !error && (
        <div className="filter-meta-bar">
          <span>Showing <strong>{events.length}</strong> events {allEvents.length > 0 && <span>(of {allEvents.length} loaded)</span>}</span>
          {isFiltered && (
            <button
              type="button"
              className="clear-filters-link"
              onClick={handleResetFilters}
            >
              Reset Filters
            </button>
          )}
        </div>
      )}

      {/* Events Table */}
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
                <th>PCAP</th>
              </tr>
            </thead>
            <tbody>
              {paginatedEvents.map((e) => (
                <tr key={e.id} className={e.isLive ? "live-row" : ""}>
                  <td className="time-cell">
                    {e.time}
                    {e.isLive && <span className="live-indicator-tag">LIVE</span>}
                  </td>
                  <td className="ip-cell">{e.ip}</td>
                  <td><span className="protocol-badge">{e.type || e.protocol}</span></td>
                  <td>{e.port}</td>
                  <td>{getThreatBadge(e)}</td>
                  <td className="details-cell" title={e.details}>
                    {e.attack_type && e.attack_type !== "BENIGN" && (
                      <span className="attack-type-tag">{e.attack_type}</span>
                    )}
                    <span className="details-text">
                      {e.attack_type && e.attack_type !== "BENIGN" && e.details.startsWith(e.attack_type)
                        ? e.details.slice(e.attack_type.length).trim()
                        : e.details}
                    </span>
                  </td>
                  <td>
                    <Link
                      to={`/packet-analysis?captureId=${e.id}`}
                      className="pcap-table-link"
                      title={`Inspect PCAP analysis for event #${e.id}`}
                      id={`pcap-link-${e.id}`}
                    >
                      <FaDatabase />
                    </Link>
                  </td>
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
          {isFiltered && (
            <button
              type="button"
              className="retry-btn"
              onClick={handleResetFilters}
            >
              Clear Filters
            </button>
          )}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="events-pagination">
          <button
            type="button"
            className="page-btn"
            disabled={currentPage === 1}
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
          >
            <FaChevronLeft />
            Previous
          </button>
          <span className="page-info">
            Page <strong>{currentPage}</strong> of <strong>{totalPages}</strong>
          </span>
          <button
            type="button"
            className="page-btn"
            disabled={currentPage === totalPages}
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
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
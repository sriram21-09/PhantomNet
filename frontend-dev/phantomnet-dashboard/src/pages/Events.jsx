// src/pages/Events.jsx
import { useState, useMemo } from "react";
import EventsTable from "../components/EventsTable";
import mockEvents from "../data/mockEvents.json";

function Events() {
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState("all"); // all | suspicious | safe
  const [sortOrder, setSortOrder] = useState("newest"); // newest | oldest

  // Helper: decide if an event is suspicious based on its details
  const isSuspicious = (event) => {
    const text = (event.details || "").toLowerCase();
    const suspiciousKeywords = [
      "failed",
      "multiple",
      "suspicious",
      "brute-force",
      "unauthorized",
      "bypass",
      "spraying",
      "attack",
      "probe",
      "anomal",
      "directory traversal",
    ];

    return suspiciousKeywords.some((word) => text.includes(word));
  };

  const filteredAndSortedEvents = useMemo(() => {
    let events = [...mockEvents];

    // 1) Search filter
    if (searchTerm.trim() !== "") {
      const term = searchTerm.toLowerCase();
      events = events.filter((event) => {
        return (
          event.timestamp.toLowerCase().includes(term) ||
          event.source_ip.toLowerCase().includes(term) ||
          event.honeypot_type.toLowerCase().includes(term) ||
          String(event.port).includes(term) ||
          event.details.toLowerCase().includes(term)
        );
      });
    }

    // 2) Suspicious / Safe filter
    if (filterType === "suspicious") {
      events = events.filter((event) => isSuspicious(event));
    } else if (filterType === "safe") {
      events = events.filter((event) => !isSuspicious(event));
    }

    // 3) Sort by timestamp
    events.sort((a, b) => {
      // timestamps are like "2025-03-01 10:23:45"
      const aTime = a.timestamp;
      const bTime = b.timestamp;

      if (sortOrder === "newest") {
        // newest first -> bigger timestamp first
        return aTime < bTime ? 1 : -1;
      } else {
        // oldest first
        return aTime > bTime ? 1 : -1;
      }
    });

    return events;
  }, [searchTerm, filterType, sortOrder]);

  return (
    <div className="events-page">
      <h1>Events</h1>
      <p>Recent events captured by PhantomNet honeypots (mock data).</p>

      {/* Search box */}
      <div className="events-controls">
        <input
          type="text"
          className="search-input"
          placeholder="Search by IP, honeypot type, or details"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </div>

      {/* Filter + sort row */}
      <div className="events-filters-row">
        {/* Filter buttons */}
        <div className="filter-group">
          <span className="filter-label">Filter:</span>
          <button
            type="button"
            className={
              filterType === "all" ? "filter-button active" : "filter-button"
            }
            onClick={() => setFilterType("all")}
          >
            All
          </button>
          <button
            type="button"
            className={
              filterType === "suspicious"
                ? "filter-button active"
                : "filter-button"
            }
            onClick={() => setFilterType("suspicious")}
          >
            Suspicious
          </button>
          <button
            type="button"
            className={
              filterType === "safe" ? "filter-button active" : "filter-button"
            }
            onClick={() => setFilterType("safe")}
          >
            Safe
          </button>
        </div>

        {/* Sort dropdown */}
        <div className="filter-group">
          <span className="filter-label">Sort:</span>
          <select
            className="sort-select"
            value={sortOrder}
            onChange={(e) => setSortOrder(e.target.value)}
          >
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
          </select>
        </div>

        {/* Count text on the right */}
        <span className="events-count">
          Showing {filteredAndSortedEvents.length} of {mockEvents.length} events
        </span>
      </div>

      {/* Events table */}
      <EventsTable
        events={filteredAndSortedEvents}
        isSuspicious={isSuspicious}
      />
    </div>
  );
}

export default Events;
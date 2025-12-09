// src/pages/Events.jsx
import { useState, useEffect } from "react";
import EventsTable from "../components/EventsTable";
import LoadingSpinner from "../components/LoadingSpinner";
import mockEvents from "../data/mockEvents.json";

function Events() {
  // loading for spinner
  const [loading, setLoading] = useState(true);

  // UI state for controls
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState("all"); // all | suspicious | safe
  const [sortOrder, setSortOrder] = useState("newest"); // newest | oldest

  // simulate async load of events
  useEffect(() => {
    const timer = setTimeout(() => setLoading(false), 600); // 0.6 sec
    return () => clearTimeout(timer);
  }, []);

  // helper: is event suspicious?
  const isSuspicious = (details) => {
    const text = details.toLowerCase();
    const keywords = ["failed", "multiple", "suspicious", "admin"];
    return keywords.some((word) => text.includes(word));
  };

  // 1) apply search + filter (all/suspicious/safe)
  const filteredEvents = mockEvents.filter((event) => {
    const text = searchTerm.toLowerCase();

    const matchesSearch =
      text === "" ||
      event.source_ip.toLowerCase().includes(text) ||
      event.honeypot_type.toLowerCase().includes(text) ||
      event.details.toLowerCase().includes(text);

    const suspicious = isSuspicious(event.details);

    const matchesFilter =
      filterType === "all" ||
      (filterType === "suspicious" && suspicious) ||
      (filterType === "safe" && !suspicious);

    return matchesSearch && matchesFilter;
  });

  // 2) sort by timestamp
  const sortedEvents = [...filteredEvents].sort((a, b) => {
    const dateA = new Date(a.timestamp.replace(" ", "T"));
    const dateB = new Date(b.timestamp.replace(" ", "T"));

    return sortOrder === "newest" ? dateB - dateA : dateA - dateB;
  });

  // while loading: show spinner only
  if (loading) {
    return (
      <div className="events">
        <h1>Events</h1>
        <p>Recent events captured by PhantomNet honeypots (mock data).</p>
        <LoadingSpinner />
      </div>
    );
  }

  // after loading: show controls + table
  return (
    <div className="events">
      <h1>Events</h1>
      <p>Recent events captured by PhantomNet honeypots (mock data).</p>

      {/* controls row */}
      <div className="events-controls">
        {/* search input */}
        <input
          type="text"
          className="events-search"
          placeholder="Search by IP, honeypot type, or details..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />

        {/* filter buttons */}
        <div className="events-filters">
          <span className="label">Filter:</span>
          <button
            className={
              filterType === "all" ? "filter-button active" : "filter-button"
            }
            onClick={() => setFilterType("all")}
          >
            All
          </button>
          <button
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
            className={
              filterType === "safe" ? "filter-button active" : "filter-button"
            }
            onClick={() => setFilterType("safe")}
          >
            Safe
          </button>
        </div>

        {/* sort dropdown */}
        <div className="events-sort">
          <span className="label">Sort:</span>
          <select
            className="sort-select"
            value={sortOrder}
            onChange={(e) => setSortOrder(e.target.value)}
          >
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
          </select>
        </div>
      </div>

{/* table with filtered + sorted events */}
      <EventsTable events={sortedEvents} />
    </div>
  );
}

export default Events;
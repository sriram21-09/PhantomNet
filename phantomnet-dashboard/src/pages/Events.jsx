// src/pages/Events.jsx
import { useState } from "react";
import EventsTable from "../components/EventsTable";
import mockEvents from "../data/mockEvents.json";

function Events() {
  // UI state
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState("all"); // all | suspicious | safe
  const [sortOrder, setSortOrder] = useState("newest"); // newest | oldest

  // Helper to decide if an event is suspicious (same logic as table colours)
  const isSuspicious = (details) => {
    const text = details.toLowerCase();
    const suspiciousKeywords = ["failed", "multiple", "suspicious", "admin"];
    return suspiciousKeywords.some((word) => text.includes(word));
  };

  // 1) Filter by search text and safe/suspicious
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

  // 2) Sort by timestamp
  const sortedEvents = [...filteredEvents].sort((a, b) => {
    const dateA = new Date(a.timestamp.replace(" ", "T"));
    const dateB = new Date(b.timestamp.replace(" ", "T"));

    if (sortOrder === "newest") {
      return dateB - dateA; // newest first
    }
    return dateA - dateB; // oldest first
  });

  return (
    <div className="events">
      <h1>Events</h1>
      <p>Recent events captured by PhantomNet honeypots (mock data).</p>

      {/* Controls: search, filter, sort */}
      <div className="events-controls">
        <input
          type="text"
          placeholder="Search by IP, type, or details..."
          className="events-search"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />

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

      {/* Table uses filtered + sorted events */}
      <EventsTable events={sortedEvents} />
    </div>
  );
}

export default Events;
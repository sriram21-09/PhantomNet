import { useState } from "react";
import mockEvents from "../data/mockEvents.json";
import EventsTable from "../components/EventsTable";

function Events() {
  const [search, setSearch] = useState("");

  // Filter events by search term
  const filteredEvents = mockEvents.filter(event =>
    event.source_ip.toLowerCase().includes(search.toLowerCase()) ||
    event.honeypot_type.toLowerCase().includes(search.toLowerCase()) ||
    event.details.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="events">
      <h1>Events</h1>
      <p>Recent events captured by PhantomNet honeypots (mock data).</p>

      {/* Search input */}
      <input
        type="text"
        className="search-box"
        placeholder="Search by IP, honeypot, or details..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />

      <EventsTable events={filteredEvents} />
    </div>
  );
}

export default Events;
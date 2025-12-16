import { useEffect, useState } from "react";
import mockEvents from "../data/mockEvents";
import "./events.css";

const Events = () => {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");

  const [events, setEvents] = useState(mockEvents);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        setLoading(true);
        setError(null);

        const res = await fetch("http://localhost:3000/api/events");
        if (!res.ok) throw new Error("Failed to fetch events");

        const data = await res.json();
        setEvents(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchEvents();
  }, []);

  // ✅ use search + filter so ESLint is happy
  const filteredEvents = events.filter((event) => {
    const matchesSearch =
      event.ip.toLowerCase().includes(search.toLowerCase()) ||
      event.details.toLowerCase().includes(search.toLowerCase());

    const matchesFilter =
      filter === "All" || event.type === filter;

    return matchesSearch && matchesFilter;
  });

  return (
    <div className="events-container">
      <h1>Events</h1>

      {/* Search + Filter UI */}
      <div className="controls">
        <input
          type="text"
          placeholder="Search by IP or details"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />

        <select value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="All">All</option>
          <option value="HTTP">HTTP</option>
          <option value="SSH">SSH</option>
          <option value="FTP">FTP</option>
          <option value="TELNET">TELNET</option>
        </select>
      </div>

      {loading && <p>Loading events...</p>}
      {error && <p className="error">{error}</p>}

      {!loading && !error && (
        <table className="events-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Honeypot Type</th>
              <th>Port</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.map((event, index) => (
              <tr key={index}>
                <td>{event.time}</td>
                <td>{event.ip}</td>
                <td>{event.type}</td>
                <td>{event.port}</td>
                <td>{event.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default Events;
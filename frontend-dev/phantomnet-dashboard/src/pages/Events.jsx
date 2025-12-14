import { useState } from "react";
import mockEvents from "../data/mockEvents";
import "./events.css";

const Events = () => {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");

  const getRowClass = (type) => {
    if (["TELNET", "FTP", "RDP", "Database"].includes(type)) {
      return "row-suspicious";
    }
    return "row-safe";
  };

  const filteredEvents = mockEvents.filter(event => {
    const matchesSearch =
      event.ip.includes(search) ||
      event.type.toLowerCase().includes(search.toLowerCase()) ||
      event.details.toLowerCase().includes(search.toLowerCase());

    const isSuspicious = ["TELNET", "FTP", "RDP", "Database"].includes(event.type);

    if (filter === "Suspicious") return matchesSearch && isSuspicious;
    if (filter === "Safe") return matchesSearch && !isSuspicious;
    return matchesSearch;
  });

  return (
    <div className="events-container">
      <h1>Events</h1>
      <p>Recent events captured by PhantomNet honeypots (mock data).</p>

      <input
        className="search"
        placeholder="Search by IP, honeypot type, or details"
        onChange={(e) => setSearch(e.target.value)}
      />

      <div className="filters">
        <button onClick={() => setFilter("All")}>All</button>
        <button onClick={() => setFilter("Suspicious")}>Suspicious</button>
        <button onClick={() => setFilter("Safe")}>Safe</button>
      </div>

      <table>
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
          {filteredEvents.map((e, i) => (
            <tr key={i} className={getRowClass(e.type)}>
              <td>{e.time}</td>
              <td>{e.ip}</td>
              <td>{e.type}</td>
              <td>{e.port}</td>
              <td>{e.details}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
export default Events;
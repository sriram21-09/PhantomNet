// src/pages/Events.jsx
import EventsTable from "../components/EventsTable";

const mockEvents = [
  {
    timestamp: "2025-03-01 10:23:45",
    source_ip: "192.168.1.10",
    honeypot_type: "SSH",
    port: 22,
    details: "Failed login attempt with user 'root'",
  },
  {
    timestamp: "2025-03-01 10:25:12",
    source_ip: "203.0.113.5",
    honeypot_type: "HTTP",
    port: 80,
    details: "GET /admin from unknown IP",
  },
  {
    timestamp: "2025-03-01 10:27:03",
    source_ip: "198.51.100.77",
    honeypot_type: "SSH",
    port: 22,
    details: "Multiple password guesses",
  },
  {
    timestamp: "2025-03-01 10:30:18",
    source_ip: "203.0.113.15",
    honeypot_type: "HTTP",
    port: 8080,
    details: "Suspicious user-agent string",
  },
  {
    timestamp: "2025-03-01 10:35:40",
    source_ip: "10.0.0.45",
    honeypot_type: "Database",
    port: 3306,
    details: "Connection attempt to MySQL service",
  },
];

function Events() {
  return (
    <div className="events">
      <h1>Events</h1>
      <p>Recent events captured by PhantomNet honeypots (mock data).</p>

      <div className="events-table-wrapper">
        <EventsTable events={mockEvents} />
      </div>
    </div>
  );
}

export default Events;
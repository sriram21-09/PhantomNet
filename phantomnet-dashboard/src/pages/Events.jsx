// src/pages/Events.jsx
import EventsTable from "../components/EventsTable";
import mockEvents from "../data/mockEvents.json";

function Events() {
  return (
    <div className="events">
      <h1>Events</h1>
      <p>Recent events captured by PhantomNet honeypots (mock data).</p>

      {/* Pass mockEvents array from JSON to EventsTable */}
      <EventsTable events={mockEvents} />
    </div>
  );
}

export default Events;
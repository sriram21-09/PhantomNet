import React from "react";
import EventsTable from "../components/EventsTable";
import mockEvents from "../data/mockEvents.json";

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
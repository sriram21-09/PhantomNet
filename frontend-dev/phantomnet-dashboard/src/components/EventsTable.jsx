// src/components/EventsTable.jsx

function EventsTable({
  events = [],
  getRowClass = () => "row-safe"
}) {
  return (
    <div className="events-table-wrapper">
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
          {events.length === 0 ? (
            <tr>
              <td colSpan="5" style={{ textAlign: "center", padding: "20px" }}>
                No events available
              </td>
            </tr>
          ) : (
            events.map((event, index) => (
              <tr key={index} className={getRowClass(event)}>
                <td>{event.timestamp}</td>
                <td>{event.source_ip}</td>
                <td>{event.honeypot_type}</td>
                <td>{event.port}</td>
                <td>{event.details}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

export default EventsTable;

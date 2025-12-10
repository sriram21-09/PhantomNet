// src/components/EventsTable.jsx

function EventsTable({ events, isSuspicious }) {
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
          {events.map((event, index) => {
            const suspicious = isSuspicious(event);

            return (
              <tr
                key={index}
                className={suspicious ? "row-suspicious" : "row-safe"}
              >
                <td>{event.timestamp}</td>
                <td>{event.source_ip}</td>
                <td>{event.honeypot_type}</td>
                <td>{event.port}</td>
                <td>{event.details}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default EventsTable;
// src/components/EventsTable.jsx

function EventsTable({ events }) {
  // Helper to decide row color based on details text
  const getRowClass = (details) => {
    const text = details.toLowerCase();

    const suspiciousKeywords = ["failed", "multiple", "suspicious", "admin"];

    const isSuspicious = suspiciousKeywords.some((word) =>
      text.includes(word)
    );

    return isSuspicious ? "row-danger" : "row-safe";
  };

  return (
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
        {events.map((event, index) => (
          <tr key={index} className={getRowClass(event.details)}>
            <td>{event.timestamp}</td>
            <td>{event.source_ip}</td>
            <td>{event.honeypot_type}</td>
            <td>{event.port}</td>
            <td>{event.details}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default EventsTable;
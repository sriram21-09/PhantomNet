const FeatureVector = ({ featureVector }) => {
  if (!featureVector) {
    return <p>No feature data available</p>;
  }

  const { eventId, protocol, features } = featureVector;

  return (
    <div className="section">
      <h2>Feature Vector Analysis</h2>

      <p>
        <strong>Event ID:</strong> {eventId}<br />
        <strong>Protocol:</strong> {protocol}
      </p>

      <table style={{ width: "100%", marginTop: "16px" }}>
        <thead>
          <tr>
            <th align="left">Feature</th>
            <th align="left">Value</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(features).map(([key, value]) => (
            <tr key={key}>
              <td>{key}</td>
              <td>{value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default FeatureVector;

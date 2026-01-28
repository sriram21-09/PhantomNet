import React from "react";
import "./FeatureVector.css";

const FeatureVector = ({ featureVector, eventId }) => {
  if (!featureVector) {
    return <p>No feature vector data available</p>;
  }

  return (
    <div className="feature-card">
      <h2>Feature Vector Analysis</h2>
      <p className="event-id">
        <strong>Event ID:</strong> {eventId}
      </p>

      <table className="feature-table">
        <thead>
          <tr>
            <th>Feature Name</th>
            <th>Value</th>
            <th>Interpretation</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(featureVector).map(([key, feature]) => (
            <tr key={key}>
              <td>{feature.label}</td>
              <td>{feature.value}</td>
              <td>{feature.interpretation}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default FeatureVector;
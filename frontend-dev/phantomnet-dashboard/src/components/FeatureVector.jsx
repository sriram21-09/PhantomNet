import React from "react";
import "./FeatureVector.css";
import ThreatIndicator from "./ThreatIndicator";


const FeatureVector = ({ featureVector, eventId }) => {
  if (!featureVector) {
    return (
      <div className="feature-vector-container">
        <p>No feature vector data available</p>
      </div>
    );
  }

  return (
    <div className="feature-vector-container">
      <h2>Feature Vector Analysis</h2>

      <p className="event-id">
        <strong>Event ID:</strong> {eventId}
      </p>

      <table className="feature-vector-table">
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
              <td>{String(feature.value)}</td>
              <td>{feature.interpretation}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default FeatureVector;

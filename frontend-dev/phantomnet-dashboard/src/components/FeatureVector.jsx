import React, { useEffect, useState } from "react";
import "../styles/components/FeatureVector.css";
import { getEventFeatures } from "../api/mlClient";
import { normalSSHEvent } from "../mocks/mlMockData";

const FeatureVector = ({ featureVector, eventId }) => {
  // ✅ Always store ONLY the features object
  const [features, setFeatures] = useState(
    (featureVector || normalSSHEvent).features
  );
  const [_loading, setLoading] = useState(false);
  const [_error, setError] = useState(null);

  useEffect(() => {
    if (!eventId) return;

    const fetchFeatures = async () => {
      setLoading(true);
      try {
        const response = await getEventFeatures(eventId);

        // ✅ Works with backend or mock shape
        setFeatures(response.features || response);
      } catch (err) {
        console.warn("API failed, using mock feature vector");
        setFeatures((featureVector || normalSSHEvent).features);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchFeatures();
  }, [eventId, featureVector]);

  // 🔹 Internal debug usage (no UI impact)
  useEffect(() => {
    if (_loading) {
      console.debug("FeatureVector: loading feature data...");
    }
    if (_error) {
      console.debug("FeatureVector error:", _error);
    }
  }, [_loading, _error]);

  if (!features) {
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
          {Object.entries(features).map(([key, feature]) => (
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

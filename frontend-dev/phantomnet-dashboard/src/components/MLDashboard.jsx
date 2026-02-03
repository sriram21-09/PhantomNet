import React, { useEffect, useState } from "react";
import { fetchMLMetrics } from "../api/mlApi";
import "../styles/ml-dashboard.css";

const MLDashboard = () => {
  const [metrics, setMetrics] = useState(null);

  useEffect(() => {
    fetchMLMetrics().then((data) => setMetrics(data));
  }, []);

  return (
    <div className="ml-dashboard">
      <h2>ML Metrics Dashboard</h2>

      {!metrics ? (
        <p>Loading ML metrics...</p>
      ) : (
        <div className="ml-metrics">
          <div className="metric-card">Accuracy: {metrics.accuracy}</div>
          <div className="metric-card">Precision: {metrics.precision}</div>
          <div className="metric-card">Recall: {metrics.recall}</div>
          <div className="metric-card">Latency: {metrics.latency}</div>
        </div>
      )}
    </div>
  );
};

export default MLDashboard;

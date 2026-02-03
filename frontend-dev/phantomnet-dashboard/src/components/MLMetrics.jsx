import { useEffect, useState } from "react";
import { fetchModelMetrics } from "../api/mlApi";

const MLMetrics = () => {
  const [metrics, setMetrics] = useState(null);

  useEffect(() => {
    fetchModelMetrics().then(setMetrics);
  }, []);

  if (!metrics) return <p>Loading model metrics...</p>;

  return (
    <div className="metric-card">
      <h3>Model Performance</h3>
      <p>Accuracy: {metrics.accuracy}</p>
      <p>F1 Score: {metrics.f1Score}</p>
      <p>Precision: {metrics.precision}</p>
      <p>Recall: {metrics.recall}</p>
    </div>
  );
};

export default MLMetrics;

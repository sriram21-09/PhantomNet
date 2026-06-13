/**
 * ML Insights Page
 * ----------------
 * Full-page view for ML model metrics, feature importance,
 * prediction distributions, and confidence analysis.
 */

import ModelMetricsDashboard from "../components/ml/ModelMetricsDashboard";

const MLInsights = () => {
  return (
    <div className="page-container">
      <ModelMetricsDashboard />
    </div>
  );
};

export default MLInsights;

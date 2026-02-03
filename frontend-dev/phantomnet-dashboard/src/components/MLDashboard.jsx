import MLMetrics from "./MLMetrics";
import ConfusionMatrix from "./ConfusionMatrix";
import FeatureImportance from "./FeatureImportance";

const MLDashboard = () => {
  return (
    <div className="ml-dashboard">
      <h2>ML Metrics Dashboard</h2>

      <MLMetrics />
      <ConfusionMatrix />
      <FeatureImportance />
    </div>
  );
};

export default MLDashboard;

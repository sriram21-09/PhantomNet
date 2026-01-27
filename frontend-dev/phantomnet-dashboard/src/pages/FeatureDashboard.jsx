import FeatureVector from "../components/FeatureVector";
import { mlMockData } from "../mocks/mlMockData";

const FeatureDashboard = () => {
  return (
    <div className="page-container">
      <FeatureVector featureVector={mlMockData} />
    </div>
  );
};

export default FeatureDashboard;

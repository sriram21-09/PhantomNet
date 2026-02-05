import { useEffect, useState } from "react";
import { fetchFeatureImportance } from "../api/mlApi";

const FeatureImportance = () => {
  const [features, setFeatures] = useState(null);

  useEffect(() => {
    fetchFeatureImportance().then(setFeatures);
  }, []);

  if (!features) return <p>Loading feature importance...</p>;

  return (
    <div className="metric-card">
      <h3>Feature Importance</h3>
      <ul>
        {features.map((f) => (
          <li key={f.feature}>
            {f.feature}: {f.importance}
          </li>
        ))}
      </ul>
    </div>
  );
};

export default FeatureImportance;

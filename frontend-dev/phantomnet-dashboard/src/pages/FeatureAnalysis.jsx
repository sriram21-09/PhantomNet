import { useContext } from "react";
import FeatureVector from "../components/FeatureVector";
import { normalSSHEvent } from "../mocks/mlMockData";
import { ThemeContext } from "../context/ThemeContext";
import "./FeatureAnalysis.css";

const FeatureAnalysis = () => {
  const { theme } = useContext(ThemeContext); // 👈 consume theme

  return (
    <div className={`feature-analysis ${theme}`}>
      <h1>Feature Analysis Dashboard</h1>

      <FeatureVector
        eventId={normalSSHEvent.eventId}
        featureVector={normalSSHEvent.features}
      />
    </div>
  );
};

export default FeatureAnalysis;

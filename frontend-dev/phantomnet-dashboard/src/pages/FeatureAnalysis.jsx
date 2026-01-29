import React from "react";
import FeatureVector from "../components/FeatureVector";
import { normalSSHEvent } from "../mocks/mlMockData";

const FeatureAnalysis = () => {
  return (
    <div style={{ padding: "20px" }}>
      <h1>Feature Analysis Dashboard</h1>

      <FeatureVector
        eventId={normalSSHEvent.eventId}
        featureVector={normalSSHEvent.features}
      />
    </div>
  );
};

export default FeatureAnalysis;

// frontend/src/components/OptimizedThreatLevel.jsx
import React from "react";
import MetricCard from "./MetricCard";

/**
 * OptimizedThreatLevel component uses React.memo to ensure it only
 * re-renders when the thread level actually changes.
 */
const OptimizedThreatLevel = React.memo(({ threatLevel }) => {
    console.log("Rendering OptimizedThreatLevel:", threatLevel);

    const getVariant = (level) => {
        if (level < 40) return "green";
        if (level < 70) return "orange";
        return "red";
    };

    return (
        <MetricCard
            title="Threat Level"
            value={`${threatLevel}%`}
            variant={getVariant(threatLevel)}
        />
    );
});

OptimizedThreatLevel.displayName = "OptimizedThreatLevel";

export default OptimizedThreatLevel;

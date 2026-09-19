import React from "react";
import PremiumMetricCard from "./PremiumMetricCard";

/**
 * OptimizedThreatLevel component uses React.memo to ensure it only
 * re-renders when the thread level actually changes.
 */
const OptimizedThreatLevel = React.memo(({ threatLevel }) => {
    const numericLevel = typeof threatLevel === "number" && !isNaN(threatLevel)
        ? Math.round(threatLevel)
        : (Number(threatLevel) && !isNaN(Number(threatLevel)) ? Math.round(Number(threatLevel)) : 0);

    const getVariant = (level) => {
        if (level < 40) return "green";
        if (level < 70) return "orange";
        return "red";
    };

    const getStatus = (level) => {
        if (level < 40) return "OPTIMAL";
        if (level < 70) return "WARNING";
        return "CRITICAL";
    };

    return (
        <PremiumMetricCard
            title="Threat Level"
            value={`${numericLevel}%`}
            variant={getVariant(numericLevel)}
            progress={numericLevel}
            subtitle="REAL-TIME MONITOR"
            status={getStatus(numericLevel)}
        />
    );
});

OptimizedThreatLevel.displayName = "OptimizedThreatLevel";

export default OptimizedThreatLevel;

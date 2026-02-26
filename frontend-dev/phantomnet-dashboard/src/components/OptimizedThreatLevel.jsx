import PremiumMetricCard from "./PremiumMetricCard";

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

    const getStatus = (level) => {
        if (level < 40) return "OPTIMAL";
        if (level < 70) return "WARNING";
        return "CRITICAL";
    };

    return (
        <PremiumMetricCard
            title="Threat Level"
            value={`${threatLevel}%`}
            variant={getVariant(threatLevel)}
            progress={threatLevel}
            subtitle="实时威胁监控"
            status={getStatus(threatLevel)}
        />
    );
});

OptimizedThreatLevel.displayName = "OptimizedThreatLevel";

export default OptimizedThreatLevel;

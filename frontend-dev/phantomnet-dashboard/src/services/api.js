// frontend/src/services/api.js

export const fetchThreatMetrics = async () => {
  const response = await fetch("/api/threat-metrics");

  if (!response.ok) {
    throw new Error("Failed to fetch threat metrics");
  }

  return await response.json();
};

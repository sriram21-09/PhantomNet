// frontend/src/services/api.js
import { apiCache } from "../utils/apiCache";

const BASE_URL = "http://localhost:8000/api";

export const fetchThreatMetrics = async () => {
  const CACHE_KEY = "threat_metrics";
  const cachedData = apiCache.get(CACHE_KEY);

  if (cachedData) {
    return cachedData;
  }

  const response = await fetch("/api/threat-metrics");

  if (!response.ok) {
    throw new Error("Failed to fetch threat metrics");
  }

  const data = await response.json();
  apiCache.set(CACHE_KEY, data, 5000); // 5s TTL
  return data;
};

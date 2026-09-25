// frontend/src/services/api.js
import { apiCache } from "../utils/apiCache";

const BASE_URL = "/api";

export const fetchThreatMetrics = async (mode = "all") => {
  const CACHE_KEY = `threat_metrics_${mode}`;
  const cachedData = apiCache.get(CACHE_KEY);

  if (cachedData) {
    return cachedData;
  }

  const response = await fetch(`${BASE_URL}/stats?mode=${mode}`);

  if (!response.ok) {
    throw new Error("Failed to fetch threat metrics");
  }

  const data = await response.json();
  apiCache.set(CACHE_KEY, data, 2000); // 2s TTL — fast refresh for real-time
  return data;
};

export const fetchSentinelStats = async () => {
  const CACHE_KEY = "sentinel_stats";
  const cachedData = apiCache.get(CACHE_KEY);

  if (cachedData) {
    return cachedData;
  }

  const response = await fetch(`${BASE_URL}/sentinel/stats`);

  if (!response.ok) {
    throw new Error("Failed to fetch sentinel stats");
  }

  const data = await response.json();
  apiCache.set(CACHE_KEY, data, 10000); // 10s TTL
  return data;
};

export const fetchTopThreatVectors = async (limit = 10, mode = "all") => {
  const CACHE_KEY = `top_threat_vectors_${limit}_${mode}`;
  const cachedData = apiCache.get(CACHE_KEY);

  if (cachedData) {
    return cachedData;
  }

  const response = await fetch(`${BASE_URL}/threats/top-vectors?limit=${limit}&mode=${mode}`);

  if (!response.ok) {
    throw new Error("Failed to fetch top threat vectors");
  }

  const data = await response.json();
  apiCache.set(CACHE_KEY, data, 5000); // 5s TTL
  return data;
};

export const fetchAttackTimeline = async (mode = "all") => {
  const CACHE_KEY = `attack_timeline_${mode}`;
  const cachedData = apiCache.get(CACHE_KEY);

  if (cachedData) {
    return cachedData;
  }

  const response = await fetch(`${BASE_URL}/stats/timeline?mode=${mode}`);

  if (!response.ok) {
    throw new Error("Failed to fetch attack timeline");
  }

  const data = await response.json();
  apiCache.set(CACHE_KEY, data, 5000); // 5s TTL
  return data;
};

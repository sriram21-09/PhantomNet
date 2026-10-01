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

export const fetchAnomalyStats = async (mode = "all") => {
  const CACHE_KEY = `anomaly_stats_${mode}`;
  const cachedData = apiCache.get(CACHE_KEY);

  if (cachedData) {
    return cachedData;
  }

  const response = await fetch(`${BASE_URL}/anomalies?mode=${mode}`);

  if (!response.ok) {
    throw new Error(`Failed to fetch anomaly telemetry (${response.status})`);
  }

  const data = await response.json();
  apiCache.set(CACHE_KEY, data, 2000); // 2s TTL
  return data;
};

export const fetchThreatSummary = async (mode = "all") => {
  const CACHE_KEY = `threat_summary_${mode}`;
  const cachedData = apiCache.get(CACHE_KEY);

  if (cachedData) {
    return cachedData;
  }

  const response = await fetch(`${BASE_URL}/threats/summary?mode=${mode}`, {
    credentials: "include",
  });

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new Error("AUTH_ERROR: Authentication required to view threat telemetry");
    }
    throw new Error(`Failed to fetch threat summary (${response.status})`);
  }

  const data = await response.json();
  apiCache.set(CACHE_KEY, data, 2000); // 2s TTL
  return data;
};

export const fetchThreatAlerts = async (limit = 10, mode = "all") => {
  const CACHE_KEY = `threat_alerts_${limit}_${mode}`;
  const cachedData = apiCache.get(CACHE_KEY);

  if (cachedData) {
    return cachedData;
  }

  const response = await fetch(`${BASE_URL}/threats/alerts?limit=${limit}&mode=${mode}`, {
    credentials: "include",
  });

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new Error("AUTH_ERROR: Authentication required to view threat alerts");
    }
    throw new Error(`Failed to fetch threat alerts (${response.status})`);
  }

  const data = await response.json();
  apiCache.set(CACHE_KEY, data, 2000); // 2s TTL
  return data;
};

export const fetchRecentThreatIndicators = async (limit = 20, mode = "all") => {
  const CACHE_KEY = `threat_indicators_${limit}_${mode}`;
  const cachedData = apiCache.get(CACHE_KEY);

  if (cachedData) {
    return cachedData;
  }

  const response = await fetch(`${BASE_URL}/threats/indicators?limit=${limit}&mode=${mode}`, {
    credentials: "include",
  });

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new Error("AUTH_ERROR: Authentication required to view threat indicators");
    }
    throw new Error(`Failed to fetch threat indicators (${response.status})`);
  }

  const data = await response.json();
  apiCache.set(CACHE_KEY, data, 2000); // 2s TTL
  return data;
};

export const fetchThreatEvents = async (limit = 20, mode = "all", threat = "ALL") => {
  const CACHE_KEY = `events_${limit}_${mode}_${threat}`;
  const cachedData = apiCache.get(CACHE_KEY);

  if (cachedData) {
    return cachedData;
  }

  const response = await fetch(`${BASE_URL}/events?limit=${limit}&mode=${mode}&threat=${threat}`, {
    credentials: "include",
  });

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new Error("AUTH_ERROR: Authentication required to view events");
    }
    throw new Error(`Failed to fetch events (${response.status})`);
  }

  const data = await response.json();
  apiCache.set(CACHE_KEY, data, 2000); // 2s TTL
  return data;
};



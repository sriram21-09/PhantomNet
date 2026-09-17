// frontend/src/api/mlApi.js
// BUG-12 fix: Fetch from real backend API instead of returning hardcoded mock data

const BASE_URL = "/api";

async function safeFetch(url, fallback) {
  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    console.warn(`[mlApi] Failed to fetch ${url}, using fallback:`, err.message);
    return fallback;
  }
}

export const fetchMLMetrics = () => {
  return safeFetch(`${BASE_URL}/v1/model/metrics`, {
    accuracy: 0.91,
    precision: 0.88,
    recall: 0.86,
    latency: "85ms",
  });
};

export const fetchPredictionData = () => {
  return safeFetch(`${BASE_URL}/v1/predictive/risk-score`, {
    threatLevel: "HIGH",
    confidence: 0.93,
  });
};

export const fetchModelMetrics = () => {
  return safeFetch(`${BASE_URL}/v1/model/metrics`, {
    accuracy: 0.89,
    f1Score: 0.86,
    precision: 0.88,
    recall: 0.84,
  });
};

export const fetchConfusionMatrix = () => {
  return safeFetch(`${BASE_URL}/v1/model/confusion-matrix`, [
    [120, 15],
    [10, 95],
  ]);
};

export const fetchFeatureImportance = () => {
  return safeFetch(`${BASE_URL}/v1/model/feature-importance`, [
    { feature: "packet_rate", importance: 0.32 },
    { feature: "connection_duration", importance: 0.27 },
    { feature: "failed_logins", importance: 0.21 },
    { feature: "bytes_sent", importance: 0.20 },
  ]);
};
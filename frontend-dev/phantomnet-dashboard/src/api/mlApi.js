// frontend/src/api/mlApi.js

export const fetchMLMetrics = () => {
  return Promise.resolve({
    accuracy: 0.91,
    precision: 0.88,
    recall: 0.86,
    latency: "85ms",
  });
};

export const fetchPredictionData = () => {
  return Promise.resolve({
    threatLevel: "HIGH",
    confidence: 0.93,
  });
};

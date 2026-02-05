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


export const fetchModelMetrics = () => {
  return Promise.resolve({
    accuracy: 0.89,
    f1Score: 0.86,
    precision: 0.88,
    recall: 0.84,
  });
};

export const fetchConfusionMatrix = () => {
  return Promise.resolve([
    [120, 15],
    [10, 95],
  ]);
};

export const fetchFeatureImportance = () => {
  return Promise.resolve([
    { feature: "packet_rate", importance: 0.32 },
    { feature: "connection_duration", importance: 0.27 },
    { feature: "failed_logins", importance: 0.21 },
    { feature: "bytes_sent", importance: 0.20 },
  ]);
};
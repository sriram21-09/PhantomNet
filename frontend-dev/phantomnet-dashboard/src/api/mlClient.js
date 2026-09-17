// src/api/mlClient.js

const BASE_URL = "/api";
// Uses Vite proxy in development, relative path in production

/**
 * Generic API request handler
 */
async function apiRequest(endpoint, options = {}) {
  const response = await fetch(`${BASE_URL}${endpoint}`, {
    headers: {
      "Content-Type": "application/json",
    },
    ...options,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(errorText || "API request failed");
  }

  return await response.json();
}

/**
 * Get ML features for a single event
 */
export async function getEventFeatures(eventId) {
  return apiRequest(`/features/event/${eventId}`);
}

/**
 * Get ML features for a batch of events
 */
export async function getBatchFeatures(eventIds = []) {
  return apiRequest(`/features/batch`, {
    method: "POST",
    body: JSON.stringify({ eventIds }),
  });
}
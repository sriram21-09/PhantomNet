// src/api/mlClient.js

const BASE_URL = "http://127.0.0.1:5000/api";
// ⬆️ placeholder — will match backend ML API later

/**
 * Generic API request handler
 */
async function apiRequest(endpoint, options = {}) {
  try {
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
  } catch (error) {
    console.error("ML API Error:", error.message);
    throw error;
  }
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
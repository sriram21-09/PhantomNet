import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

import "./Styles/App.css";
import "./Styles/index.css";
import "./Styles/theme.css";
import axios from "axios";

// Automatically attach X-Requested-With: XMLHttpRequest to all API requests for CSRF protection compliance
axios.defaults.headers.common["X-Requested-With"] = "XMLHttpRequest";
axios.defaults.withCredentials = true;

// Centralized Axios request interceptor for same-origin CSRF compliance
axios.interceptors.request.use((config) => {
  const url = config.url || "";
  const isSameOriginOrRelative =
    url.startsWith("/") ||
    (typeof window !== "undefined" && url.startsWith(window.location.origin));

  if (isSameOriginOrRelative) {
    config.withCredentials = true;
    const method = (config.method || "get").toLowerCase();
    if (["post", "put", "patch", "delete"].includes(method)) {
      config.headers = config.headers || {};
      if (!config.headers["X-Requested-With"] && !config.headers["x-requested-with"]) {
        config.headers["X-Requested-With"] = "XMLHttpRequest";
      }
    }
  }
  return config;
});

const originalFetch = window.fetch;
window.fetch = async (input, init = {}) => {
  const url = typeof input === "string" ? input : input?.url || "";
  const isSameOriginOrRelative =
    url.startsWith("/api") ||
    (typeof window !== "undefined" && url.startsWith(window.location.origin + "/api"));

  if (isSameOriginOrRelative) {
    const headers = new Headers(init.headers || (typeof input === "object" && input.headers ? input.headers : {}));
    if (!headers.has("X-Requested-With") && !headers.has("x-requested-with")) {
      headers.set("X-Requested-With", "XMLHttpRequest");
    }
    const credentials = init.credentials || (typeof input === "object" && input.credentials ? input.credentials : "include");
    return originalFetch(input, { ...init, headers, credentials });
  }
  return originalFetch(input, init);
};

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

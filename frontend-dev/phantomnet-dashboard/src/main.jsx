import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

import "./Styles/App.css";
import "./Styles/index.css";
import "./Styles/theme.css";
// Automatically attach X-Requested-With: XMLHttpRequest to all API requests for CSRF protection compliance
const originalFetch = window.fetch;
window.fetch = async (input, init = {}) => {
  const url = typeof input === "string" ? input : input?.url || "";
  if (url.startsWith("/api") || url.startsWith(window.location.origin + "/api")) {
    const headers = new Headers(init.headers || (typeof input === "object" && input.headers ? input.headers : {}));
    if (!headers.has("X-Requested-With") && !headers.has("x-requested-with")) {
      headers.set("X-Requested-With", "XMLHttpRequest");
    }
    return originalFetch(input, { ...init, headers });
  }
  return originalFetch(input, init);
};

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

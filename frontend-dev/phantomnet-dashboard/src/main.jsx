import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

import "./App.css";
import "./index.css";
import "./theme.css";   // 👈 ADD THIS LINE

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

import "./styles/App.css";
import "./styles/index.css";
import "./styles/theme.css";   // 👈 ADD THIS LINE

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

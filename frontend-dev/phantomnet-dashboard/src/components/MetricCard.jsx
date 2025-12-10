import React from "react";

function MetricCard({ title, value, accent = "blue" }) {
  return (
    <div className={`metric-card metric-card--${accent}`}>
      <div className="metric-title">{title}</div>
      <div className="metric-value">{value}</div>
    </div>
  );
}

export default MetricCard;
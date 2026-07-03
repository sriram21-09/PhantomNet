import React from "react";
import {
  FaBookOpen,
  FaClock,
  FaCheckCircle,
  FaTimesCircle,
} from "react-icons/fa";
import "../Styles/components/SentinelStatsWidget.css";

const sentinelCards = [
  {
    key: "total_playbooks",
    title: "Playbooks Generated",
    subtitle: "TOTAL PIPELINE OUTPUT",
    icon: FaBookOpen,
    variant: "purple",
  },
  {
    key: "pending",
    title: "Pending Review",
    subtitle: "AWAITING ANALYST",
    icon: FaClock,
    variant: "amber",
  },
  {
    key: "approved",
    title: "Approved",
    subtitle: "DEPLOYMENT READY",
    icon: FaCheckCircle,
    variant: "emerald",
  },
  {
    key: "rejected",
    title: "Rejected",
    subtitle: "FLAGGED FOR REVIEW",
    icon: FaTimesCircle,
    variant: "rose",
  },
];

const SentinelStatsWidget = ({ stats, loading, error }) => {
  if (error) return null;

  return (
    <div className="sentinel-stats-section">
      <div className="sentinel-stats-header">
        <div className="sentinel-header-badge hud-font">SENTINEL_LAYER</div>
        <h3 className="sentinel-header-title glow-text">
          Playbook Intelligence
        </h3>
        <p className="sentinel-header-subtitle text-dim">
          AUTOMATED RESPONSE PIPELINE STATUS
        </p>
      </div>

      <div className="sentinel-stats-grid">
        {sentinelCards.map((card) => {
          const Icon = card.icon;
          const value = loading ? "—" : (stats?.[card.key] ?? "N/A");

          return (
            <div
              key={card.key}
              className={`sentinel-stat-card sentinel-variant-${card.variant} hud-font ${loading ? "sentinel-loading" : ""}`}
              id={`sentinel-stat-${card.key}`}
            >
              <div className="sentinel-card-accent"></div>
              <div className="sentinel-card-inner">
                <div className="sentinel-card-top">
                  <div className={`sentinel-icon-wrap sentinel-variant-${card.variant}`}>
                    <Icon />
                  </div>
                  <div className="sentinel-pulse-dot"></div>
                </div>
                <div className="sentinel-card-value">
                  {typeof value === "number" ? value.toLocaleString() : value}
                </div>
                <div className="sentinel-card-info">
                  <h4 className="sentinel-card-title">{card.title}</h4>
                  <p className="sentinel-card-subtitle">{card.subtitle}</p>
                </div>
                <div className="sentinel-card-bar">
                  <div
                    className="sentinel-card-bar-fill"
                    style={{
                      width: loading
                        ? "0%"
                        : stats?.total_playbooks > 0
                        ? `${Math.min(((stats?.[card.key] ?? 0) / stats.total_playbooks) * 100, 100)}%`
                        : card.key === "total_playbooks"
                        ? "100%"
                        : "0%",
                    }}
                  ></div>
                </div>
              </div>
              <div className="sentinel-card-glow"></div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default SentinelStatsWidget;

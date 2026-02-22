import {
  FaChartLine,
  FaNetworkWired,
  FaServer,
  FaShieldAlt,
  FaExclamationTriangle
} from "react-icons/fa";
import "../styles/components/MetricCard.css";

const iconMap = {
  blue: FaChartLine,
  cyan: FaNetworkWired,
  green: FaServer,
  orange: FaShieldAlt,
  red: FaExclamationTriangle,
};

const MetricCard = ({ title, value, variant = "blue" }) => {
  const Icon = iconMap[variant] || FaChartLine;

  return (
    <div className={`metric-card variant-${variant}`} title={`Real-time telemetry for ${title}`}>
      <div className="metric-glow"></div>
      <div className="metric-content">
        <div className="metric-header">
          <span className="metric-title glow-text">{title}</span>
          <div className="metric-icon">
            <Icon />
          </div>
        </div>
        <div className="metric-value">
          {typeof value === 'number' ? value.toLocaleString() : value}
        </div>
        <div className="metric-bar">
          <div className="metric-bar-fill" style={{ background: `var(--color-${variant})` }}></div>
        </div>
      </div>
    </div>
  );
};

export default MetricCard;

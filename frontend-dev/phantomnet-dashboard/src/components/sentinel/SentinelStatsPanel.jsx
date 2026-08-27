import React, { useState, useMemo } from "react";
import PropTypes from "prop-types";
import {
  FaBookOpen,
  FaClock,
  FaCheckCircle,
  FaTimesCircle,
} from "react-icons/fa";
import "../../Styles/components/SentinelStatsPanel.css";

const SentinelStatsPanel = ({ stats, loading }) => {
  const [hoveredTrend, setHoveredTrend] = useState(null);
  const [activeSeverity, setActiveSeverity] = useState(null);

  // 1. Safe extraction and normalization
  const total = stats?.total_playbooks || 0;
  const approved = (stats?.approved || 0) + (stats?.exported || 0);
  const pending = stats?.pending || 0;
  const rejected = stats?.rejected || 0;
  const approvalRate = stats?.approval_rate !== undefined ? stats.approval_rate : 0;

  // 2. Summary Card configurations
  const summaryCards = [
    {
      key: "total",
      title: "Playbooks Generated",
      subtitle: "TOTAL PIPELINE OUTPUT",
      value: total,
      icon: FaBookOpen,
      variant: "purple",
      percent: 100,
    },
    {
      key: "pending",
      title: "Pending Review",
      subtitle: "AWAITING ANALYST APPROVAL",
      value: pending,
      icon: FaClock,
      variant: "amber",
      percent: total > 0 ? (pending / total) * 100 : 0,
    },
    {
      key: "approved",
      title: "Approved Playbooks",
      subtitle: "READY FOR DEPLOYMENT",
      value: approved,
      icon: FaCheckCircle,
      variant: "emerald",
      percent: total > 0 ? (approved / total) * 100 : 0,
    },
    {
      key: "rejected",
      title: "Rejected Playbooks",
      subtitle: "FLAGGED AND ARCHIVED",
      value: rejected,
      icon: FaTimesCircle,
      variant: "rose",
      percent: total > 0 ? (rejected / total) * 100 : 0,
    },
  ];

  // 3. Severity distribution donut chart calculation
  const severityDistribution = useMemo(() => {
    const raw = stats?.severity_distribution || {};
    const normalized = {
      critical: raw.critical || raw.CRITICAL || 0,
      high: raw.high || raw.HIGH || 0,
      medium: raw.medium || raw.MEDIUM || 0,
      low: raw.low || raw.LOW || 0,
    };

    const hasData = Object.values(normalized).some((v) => v > 0);
    const data = hasData
      ? normalized
      : { critical: 0, high: 0, medium: 0, low: 0 };

    const sum = Object.values(data).reduce((acc, curr) => acc + curr, 0);

    const categories = [
      { name: "critical", count: data.critical, color: "#f43f5e", glow: "rgba(244,63,94,0.4)" },
      { name: "high", count: data.high, color: "#fb923c", glow: "rgba(251,146,60,0.4)" },
      { name: "medium", count: data.medium, color: "#38bdf8", glow: "rgba(56,189,248,0.4)" },
      { name: "low", count: data.low, color: "#34d399", glow: "rgba(52,211,153,0.4)" },
    ];

    let cumulativeLength = 0;
    const segments = categories.map((cat) => {
      const percent = sum > 0 ? cat.count / sum : 0;
      const strokeLength = percent * 314.159;
      const strokeOffset = -cumulativeLength;
      cumulativeLength += strokeLength;

      return {
        ...cat,
        percent,
        strokeLength,
        strokeOffset,
      };
    });

    return { segments, sum, hasData };
  }, [stats]);

  // 4. Daily trend timeline line/area calculations
  const timelineData = useMemo(() => {
    const trends = stats?.generation_trends || [];
    const hasData = trends.length > 0;

    const rawData = trends;
    const counts = rawData.map((d) => Number(d.count) || 0);
    const maxCount = counts.length > 0 ? Math.max(...counts, 4) : 4;
    const width = 500;
    const height = 200;
    const paddingLeft = 40;
    const paddingRight = 20;
    const paddingTop = 25;
    const paddingBottom = 30;

    const chartWidth = width - paddingLeft - paddingRight;
    const chartHeight = height - paddingTop - paddingBottom;

    const points = rawData.map((d, i) => {
      const denom = (rawData.length - 1) > 0 ? (rawData.length - 1) : 1;
      const x = paddingLeft + (i / denom) * chartWidth;
      const cnt = Number(d.count) || 0;
      const y = height - paddingBottom - (cnt / maxCount) * chartHeight;

      // Extract brief date string e.g. "2026-07-28" -> "07/28"
      let dateLabel = d.date || "";
      if (d.date && typeof d.date === "string" && d.date.includes("-")) {
        const parts = d.date.split("-");
        if (parts.length >= 3) {
          dateLabel = `${parts[1]}/${parts[2]}`;
        }
      }

      return {
        x,
        y,
        date: d.date,
        label: dateLabel,
        count: cnt,
      };
    });

    // Construct line SVG path
    const linePath = points.length > 0
      ? points.reduce(
          (path, pt, i) => (i === 0 ? `M ${pt.x},${pt.y}` : `${path} L ${pt.x},${pt.y}`),
          ""
        )
      : "";

    // Construct area closed path
    const areaPath = points.length > 0
      ? `${linePath} L ${points[points.length - 1].x},${height - paddingBottom} L ${points[0].x},${height - paddingBottom} Z`
      : "";

    return { points, linePath, areaPath, hasData, height, paddingBottom, maxCount };
  }, [stats]);

  // Render Loader Skeleton if loading
  if (loading) {
    return (
      <div className="sentinel-stats-section">
        <div className="sentinel-stats-grid">
          {Array.from({ length: 4 }).map((_, idx) => (
            <div key={idx} className="sentinel-stat-card sentinel-loading hud-font">
              <div className="sentinel-card-accent" style={{ background: "rgba(255,255,255,0.05)" }}></div>
              <div className="sentinel-card-inner" style={{ height: "100px", justifyContent: "center" }}>
                <div style={{ width: "30px", height: "30px", background: "rgba(255,255,255,0.05)", borderRadius: "6px", marginBottom: "10px" }}></div>
                <div style={{ width: "60px", height: "20px", background: "rgba(255,255,255,0.05)", borderRadius: "4px" }}></div>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="sentinel-stats-section">
      {/* 4 Summary Cards Grid */}
      <div className="sentinel-stats-grid">
        {summaryCards.map((card) => {
          const Icon = card.icon;
          return (
            <div
              key={card.key}
              className={`sentinel-stat-card sentinel-variant-${card.variant} hud-font`}
              id={`sentinel-stat-${card.key}`}
            >
              <div className="sentinel-card-accent"></div>
              <div className="sentinel-card-inner">
                <div className="sentinel-card-top">
                  <div className="sentinel-icon-wrap">
                    <Icon />
                  </div>
                  <div className="sentinel-pulse-dot"></div>
                </div>
                <div className="sentinel-card-value">
                  {card.value.toLocaleString()}
                </div>
                <div className="sentinel-card-info">
                  <h4 className="sentinel-card-title">{card.title}</h4>
                  <p className="sentinel-card-subtitle">{card.subtitle}</p>
                </div>
                <div className="sentinel-card-bar">
                  <div
                    className="sentinel-card-bar-fill"
                    style={{ width: `${card.percent}%` }}
                  ></div>
                </div>
              </div>
              <div className="sentinel-card-glow"></div>
            </div>
          );
        })}
      </div>

      {/* Visual Analytics Charts Row */}
      <div className="sentinel-charts-grid">
        {/* Donut Chart: Severity Distribution */}
        <div className="sentinel-chart-card hud-font">
          <div className="sentinel-chart-header">
            <h4 className="sentinel-chart-title">Severity Distribution</h4>
            <p className="sentinel-chart-subtitle">
              {severityDistribution.hasData ? "LIVE PLAYBOOK METRICS" : "NO ACTIVE PLAYBOOKS"}
            </p>
          </div>
          <div className="sentinel-chart-wrapper">
            <svg viewBox="0 0 200 200" className="sentinel-svg-canvas">
              <circle
                cx="100"
                cy="100"
                r="50"
                fill="transparent"
                stroke="rgba(255,255,255,0.02)"
                strokeWidth="15"
              />
              {/* Back track / neutral ring when there is no data */}
              {!severityDistribution.hasData && (
                <circle
                  cx="100"
                  cy="100"
                  r="50"
                  fill="transparent"
                  stroke="#1e293b"
                  strokeWidth="14"
                />
              )}
              {severityDistribution.segments.map((seg, i) => (
                <circle
                  key={i}
                  cx="100"
                  cy="100"
                  r="50"
                  fill="transparent"
                  stroke={seg.color}
                  strokeDasharray={seg.strokeLength + " 314.159"}
                  strokeDashoffset={seg.strokeOffset}
                  transform="rotate(-90 100 100)"
                  className="donut-segment"
                  onMouseEnter={() => severityDistribution.hasData && setActiveSeverity(seg.name)}
                  onMouseLeave={() => severityDistribution.hasData && setActiveSeverity(null)}
                  style={{
                    color: seg.color,
                    strokeWidth: activeSeverity === seg.name ? "18px" : "14px",
                  }}
                />
              ))}
              <text
                x="100"
                y="95"
                textAnchor="middle"
                className="donut-center-text"
                fontSize="18"
              >
                {severityDistribution.sum}
              </text>
              <text
                x="100"
                y="115"
                textAnchor="middle"
                fontSize="9"
                fill="#64748b"
                fontWeight="700"
                letterSpacing="1px"
              >
                RULES
              </text>
            </svg>
          </div>
          <div className="donut-legend">
            {severityDistribution.segments.map((seg, i) => (
              <div
                key={i}
                className="legend-item"
                onMouseEnter={() => setActiveSeverity(seg.name)}
                onMouseLeave={() => setActiveSeverity(null)}
                style={{
                  background: activeSeverity === seg.name ? "rgba(255,255,255,0.03)" : "transparent",
                }}
              >
                <span className="legend-color" style={{ background: seg.color }}></span>
                <span className="legend-name">{seg.name}</span>
                <span className="legend-val">{seg.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Gauge Chart: Approval Rate */}
        <div className="sentinel-chart-card hud-font">
          <div className="sentinel-chart-header">
            <h4 className="sentinel-chart-title">Analyst Approval Rate</h4>
            <p className="sentinel-chart-subtitle">PIPELINE EFFICIENCY RATING</p>
          </div>
          <div className="sentinel-chart-wrapper">
            <svg viewBox="0 0 200 200" className="sentinel-svg-canvas">
              <defs>
                <linearGradient id="emerald-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#10b981" />
                  <stop offset="100%" stopColor="#34d399" />
                </linearGradient>
              </defs>
              {/* Back track */}
              <circle
                cx="100"
                cy="100"
                r="55"
                fill="transparent"
                className="gauge-bg"
                strokeWidth="10"
              />
              {/* Fore fill */}
              <circle
                cx="100"
                cy="100"
                r="55"
                fill="transparent"
                stroke="url(#emerald-grad)"
                strokeWidth="10"
                strokeDasharray="345.575"
                strokeDashoffset={345.575 - (345.575 * approvalRate) / 100}
                transform="rotate(-90 100 100)"
                strokeLinecap="round"
                className="gauge-fill"
              />
              <text
                x="100"
                y="98"
                textAnchor="middle"
                className="gauge-val-text"
                fontSize="20"
              >
                {approvalRate}%
              </text>
              <text
                x="100"
                y="118"
                textAnchor="middle"
                className="gauge-label-text"
                fontSize="8"
              >
                APPROVED RATIO
              </text>
            </svg>
          </div>
          <div className="gauge-stats-row">
            <div className="gauge-substat">
              <span className="gauge-substat-val" style={{ color: "var(--color-success, #34d399)" }}>
                {approved}
              </span>
              <span className="gauge-substat-label">APPROVED</span>
            </div>
            <div className="gauge-substat">
              <span className="gauge-substat-val" style={{ color: "var(--color-alert, #fb7185)" }}>
                {rejected}
              </span>
              <span className="gauge-substat-label">REJECTED</span>
            </div>
            <div className="gauge-substat">
              <span className="gauge-substat-val" style={{ color: "var(--color-primary, #a78bfa)" }}>
                {pending}
              </span>
              <span className="gauge-substat-label">PENDING</span>
            </div>
          </div>
        </div>

        {/* Line Chart: Generation Timeline */}
        <div className="sentinel-chart-card hud-font">
          <div className="sentinel-chart-header">
            <h4 className="sentinel-chart-title">Generation Timeline</h4>
            <p className="sentinel-chart-subtitle">
              {timelineData.hasData ? "DAILY RULE CREATIONS" : "NO HISTORY RECORDED"}
            </p>
          </div>
          <div className="sentinel-chart-wrapper" style={{ overflow: "visible", position: "relative" }}>
            <svg viewBox="0 0 500 200" className="sentinel-svg-canvas" style={{ overflow: "visible", opacity: timelineData.hasData ? 1 : 0.15 }}>
              <defs>
                <linearGradient id="timeline-area-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#8b5cf6" stopOpacity="0.25" />
                  <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0.0" />
                </linearGradient>
                <linearGradient id="line-grad" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="#8b5cf6" />
                  <stop offset="50%" stopColor="#c084fc" />
                  <stop offset="100%" stopColor="#6366f1" />
                </linearGradient>
              </defs>

              {/* Gridlines */}
              {[0, 0.25, 0.5, 0.75, 1].map((f, idx) => {
                const y = 25 + f * 145;
                const gridVal = Math.round(timelineData.maxCount * (1 - f));
                return (
                  <g key={idx}>
                    <line
                      x1="40"
                      y1={y}
                      x2="480"
                      y2={y}
                      className="timeline-gridline"
                    />
                    <text
                      x="32"
                      y={y + 3}
                      textAnchor="end"
                      className="timeline-axis-text"
                    >
                      {gridVal}
                    </text>
                  </g>
                );
              })}

              {/* Gradient Area under line */}
              {timelineData.areaPath && (
                <path d={timelineData.areaPath} fill="url(#timeline-area-grad)" />
              )}

              {/* Connection Line */}
              {timelineData.linePath && (
                <path
                  d={timelineData.linePath}
                  fill="none"
                  stroke="url(#line-grad)"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  className="timeline-line"
                />
              )}

              {/* Data points */}
              {timelineData.points.map((pt, idx) => {
                const isHovered = hoveredTrend?.idx === idx;
                return (
                  <g key={idx}>
                    <circle
                      cx={pt.x}
                      cy={pt.y}
                      r={isHovered ? "5.5" : "3.5"}
                      fill={isHovered ? "#ffffff" : "#a78bfa"}
                      stroke="#8b5cf6"
                      strokeWidth={isHovered ? "2.5" : "1.5"}
                      className="timeline-point"
                      onMouseEnter={(e) => {
                        const circleRect = e.currentTarget.getBoundingClientRect();
                        const wrapperRect = e.currentTarget.ownerSVGElement.parentElement.getBoundingClientRect();
                        const tooltipX = circleRect.left - wrapperRect.left + circleRect.width / 2;
                        const tooltipY = circleRect.top - wrapperRect.top;
                        setHoveredTrend({
                          idx,
                          date: pt.date,
                          label: pt.label,
                          count: pt.count,
                          tooltipX,
                          tooltipY,
                        });
                      }}
                      onMouseLeave={() => setHoveredTrend(null)}
                    />
                    {/* X axis Labels */}
                    {idx % Math.max(Math.floor(timelineData.points.length / 5), 1) === 0 && (
                      <text
                        x={pt.x}
                        y="185"
                        textAnchor="middle"
                        className="timeline-axis-text"
                      >
                        {pt.label}
                      </text>
                    )}
                  </g>
                );
              })}
            </svg>

            {!timelineData.hasData && (
              <div className="timeline-empty-overlay hud-font">
                <div className="empty-title glow-text">NO_GENERATION_HISTORY</div>
                <p className="empty-subtitle">Generate playbook response rules to view creation trends.</p>
              </div>
            )}

            {/* Custom Interactive Tooltip */}
            {hoveredTrend && (
              <div
                className="timeline-tooltip active"
                style={{
                  left: `${hoveredTrend.tooltipX}px`,
                  top: `${hoveredTrend.tooltipY}px`,
                }}
              >
                <div className="tooltip-date">{hoveredTrend.date || "Date Unknown"}</div>
                <div className="tooltip-val">
                  <span>Playbooks:</span>
                  <span className="tooltip-val-num" style={{ color: "var(--color-primary, #a78bfa)" }}>
                    {hoveredTrend.count}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

SentinelStatsPanel.propTypes = {
  stats: PropTypes.shape({
    total_playbooks: PropTypes.number,
    pending: PropTypes.number,
    approved: PropTypes.number,
    rejected: PropTypes.number,
    approval_rate: PropTypes.number,
    severity_distribution: PropTypes.object,
    avg_threat_score: PropTypes.number,
    avg_confidence_score: PropTypes.number,
    generation_trends: PropTypes.arrayOf(
      PropTypes.shape({
        date: PropTypes.string,
        count: PropTypes.number,
      })
    ),
  }),
  loading: PropTypes.bool,
};

export default SentinelStatsPanel;

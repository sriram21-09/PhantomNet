import React, { useState, useEffect, useMemo, useCallback } from "react";
import PropTypes from "prop-types";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceDot,
} from "recharts";
import {
  FaChartLine,
  FaBolt,
  FaExclamationTriangle,
  FaClock,
  FaSyncAlt,
  FaLayerGroup,
  FaShieldAlt,
} from "react-icons/fa";
import axios from "axios";

/**
 * Custom Tooltip for Attack Spikes & Anomaly Timestamps
 */
const CustomTimelineTooltip = ({ active, payload, label }) => {
  if (!active || !payload || !payload.length) return null;

  const data = payload[0].payload;
  const count = data.count || data.density || 0;
  const isSpike = data.is_spike;
  const isAnomaly = data.is_anomaly;
  const anomalyType = data.anomaly_type || (isSpike ? "Attack Spike Surge" : isAnomaly ? "Traffic Anomaly" : null);

  return (
    <div className="bg-slate-950/95 border border-slate-700/80 rounded-xl p-3.5 shadow-2xl backdrop-blur-md max-w-xs text-xs space-y-2 z-50">
      <div className="flex items-center justify-between border-b border-slate-800 pb-2 text-slate-300 gap-3">
        <span className="flex items-center gap-1.5 font-medium text-slate-200">
          <FaClock className="text-cyan-400 text-[11px]" />
          {label}
        </span>
        <span
          className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider ${
            isSpike
              ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
              : isAnomaly
              ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
              : "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
          }`}
        >
          {isSpike ? "Critical Spike" : isAnomaly ? "Anomaly" : "Normal"}
        </span>
      </div>

      <div className="flex items-baseline justify-between pt-0.5">
        <span className="text-slate-400">Event Density:</span>
        <span className="text-base font-bold text-slate-100 font-mono">
          {count}{" "}
          <span className="text-[10px] text-slate-400 font-normal">events</span>
        </span>
      </div>

      {anomalyType && (
        <div className={`p-2 rounded-lg text-[11px] flex items-start gap-2 ${
          isSpike
            ? "bg-rose-950/50 border border-rose-800/60 text-rose-200"
            : "bg-amber-950/50 border border-amber-800/60 text-amber-200"
        }`}>
          {isSpike ? (
            <FaBolt className="text-rose-400 text-xs shrink-0 mt-0.5 animate-pulse" />
          ) : (
            <FaExclamationTriangle className="text-amber-400 text-xs shrink-0 mt-0.5" />
          )}
          <div>
            <div className="font-semibold text-slate-100">{anomalyType}</div>
            <div className="text-[10px] opacity-80 mt-0.5">
              {isSpike
                ? "Attack density surge exceeds baseline safety limits"
                : "Unusual temporal concentration of network events"}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

CustomTimelineTooltip.propTypes = {
  active: PropTypes.bool,
  payload: PropTypes.array,
  label: PropTypes.string,
};

/**
 * Custom Data Dot Renderer for Line Chart Data Points
 */
const CustomDot = (props) => {
  const { cx, cy, payload } = props;

  if (!cx || !cy) return null;

  if (payload.is_spike) {
    return (
      <g key={`dot-spike-${payload.timestamp}`}>
        <circle cx={cx} cy={cy} r={7} fill="#ef4444" fillOpacity={0.3} className="animate-ping" />
        <circle cx={cx} cy={cy} r={5} fill="#ef4444" stroke="#ffffff" strokeWidth={1.5} />
      </g>
    );
  }

  if (payload.is_anomaly) {
    return (
      <circle
        key={`dot-anomaly-${payload.timestamp}`}
        cx={cx}
        cy={cy}
        r={4.5}
        fill="#f59e0b"
        stroke="#1e293b"
        strokeWidth={1.5}
      />
    );
  }

  return (
    <circle
      key={`dot-normal-${payload.timestamp}`}
      cx={cx}
      cy={cy}
      r={3}
      fill="#10b981"
      stroke="#0f172a"
      strokeWidth={1}
    />
  );
};

CustomDot.propTypes = {
  cx: PropTypes.number,
  cy: PropTypes.number,
  payload: PropTypes.object,
};

/**
 * CampaignTimelineChart Component
 * Visualizes attack event density line chart over campaign duration inside PlaybookViewer.
 */
export default function CampaignTimelineChart({
  timelineData = null,
  campaignId = "CMP-ACTIVE",
  className = "",
}) {
  const [data, setData] = useState(timelineData || []);
  const [isLoading, setIsLoading] = useState(!timelineData || timelineData.length === 0);
  const [timeFilter, setTimeFilter] = useState("ALL");

  const fetchTimelineData = useCallback(async () => {
    try {
      setIsLoading(true);
      const res = await axios.get(`/api/sentinel/campaigns/${campaignId}/timeline`);
      if (res.data && res.data.timeline) {
        setData(res.data.timeline);
      }
    } catch (err) {
      console.warn("Failed to fetch campaign timeline API, fallback to mock points:", err);
      // Fallback fallback time-series if backend network fails
      setData([
        { timestamp: "08-08 04:00", count: 14, is_spike: false, is_anomaly: false },
        { timestamp: "08-08 06:00", count: 22, is_spike: false, is_anomaly: false },
        { timestamp: "08-08 08:00", count: 68, is_spike: true, is_anomaly: true, anomaly_type: "Initial Recon Spike" },
        { timestamp: "08-08 10:00", count: 45, is_spike: false, is_anomaly: true, anomaly_type: "Elevated Scan Rate" },
        { timestamp: "08-08 12:00", count: 135, is_spike: true, is_anomaly: true, anomaly_type: "SYN Flood Surge Peak" },
        { timestamp: "08-08 14:00", count: 82, is_spike: false, is_anomaly: true, anomaly_type: "Brute Force Burst" },
        { timestamp: "08-08 16:00", count: 31, is_spike: false, is_anomaly: false },
        { timestamp: "08-08 18:00", count: 94, is_spike: true, is_anomaly: true, anomaly_type: "Data Exfiltration Peak" },
        { timestamp: "08-08 20:00", count: 26, is_spike: false, is_anomaly: false },
      ]);
    } finally {
      setIsLoading(false);
    }
  }, [campaignId]);

  useEffect(() => {
    if (timelineData && timelineData.length > 0) {
      setData(timelineData);
      setIsLoading(false);
    } else {
      fetchTimelineData();
    }
  }, [timelineData, fetchTimelineData]);

  // Filtered dataset according to timeFilter
  const filteredData = useMemo(() => {
    if (!data || data.length === 0) return [];
    if (timeFilter === "1H") return data.slice(-4);
    if (timeFilter === "6H") return data.slice(-7);
    return data;
  }, [data, timeFilter]);

  // Summary Metrics
  const metrics = useMemo(() => {
    if (!data || data.length === 0) return { total: 0, peak: 0, spikes: 0, anomalies: 0 };
    const total = data.reduce((acc, curr) => acc + (curr.count || curr.density || 0), 0);
    const peak = Math.max(...data.map((d) => d.count || d.density || 0));
    const spikes = data.filter((d) => d.is_spike).length;
    const anomalies = data.filter((d) => d.is_anomaly).length;
    return { total, peak, spikes, anomalies };
  }, [data]);

  return (
    <div
      className={`bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-xl backdrop-blur-md space-y-3.5 text-slate-100 ${className}`}
      id="campaign-timeline-chart-container"
    >
      {/* Header & Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <FaChartLine className="text-sm" />
          </div>
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              Campaign Event Density Timeline
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-cyan-400 border border-slate-700">
                {campaignId}
              </span>
            </h4>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Progression over campaign duration with anomaly timestamps & attack spike peaks
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center bg-slate-950/80 p-0.5 rounded-lg border border-slate-800 text-[10px] font-medium">
            {["ALL", "6H", "1H"].map((f) => (
              <button
                key={f}
                onClick={() => setTimeFilter(f)}
                className={`px-2.5 py-1 rounded-md transition-all ${
                  timeFilter === f
                    ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/40 shadow-sm"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {f}
              </button>
            ))}
          </div>

          <button
            onClick={fetchTimelineData}
            title="Refresh Timeline Data"
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors border border-slate-700 text-xs"
          >
            <FaSyncAlt className={isLoading ? "animate-spin" : ""} />
          </button>
        </div>
      </div>

      {/* KPI Stats Summary Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-2.5 flex items-center gap-2.5">
          <FaLayerGroup className="text-cyan-400 text-base" />
          <div>
            <div className="text-[10px] text-slate-400 uppercase font-semibold">Total Events</div>
            <div className="text-sm font-bold text-slate-100 font-mono">{metrics.total}</div>
          </div>
        </div>

        <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-2.5 flex items-center gap-2.5">
          <FaShieldAlt className="text-emerald-400 text-base" />
          <div>
            <div className="text-[10px] text-slate-400 uppercase font-semibold">Peak Density</div>
            <div className="text-sm font-bold text-slate-100 font-mono">{metrics.peak} <span className="text-[9px] text-slate-500 font-normal">/min</span></div>
          </div>
        </div>

        <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-2.5 flex items-center gap-2.5">
          <FaBolt className="text-rose-400 text-base" />
          <div>
            <div className="text-[10px] text-slate-400 uppercase font-semibold">Attack Spikes</div>
            <div className="text-sm font-bold text-rose-400 font-mono">{metrics.spikes}</div>
          </div>
        </div>

        <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-2.5 flex items-center gap-2.5">
          <FaExclamationTriangle className="text-amber-400 text-base" />
          <div>
            <div className="text-[10px] text-slate-400 uppercase font-semibold">Anomalies</div>
            <div className="text-sm font-bold text-amber-400 font-mono">{metrics.anomalies}</div>
          </div>
        </div>
      </div>

      {/* Chart Canvas Area */}
      <div className="h-48 w-full pt-2">
        {isLoading ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-400 gap-2">
            <FaSyncAlt className="animate-spin text-cyan-400" />
            Loading campaign time-series data...
          </div>
        ) : filteredData.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-500">
            No campaign timeline data available for selected filter.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={filteredData}
              margin={{ top: 12, right: 12, left: -20, bottom: 0 }}
            >
              <defs>
                <linearGradient id="campaignDensityGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.45} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                </linearGradient>
              </defs>

              <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.4} />

              <XAxis
                dataKey="timestamp"
                stroke="#64748b"
                tick={{ fill: "#94a3b8", fontSize: 10 }}
                tickFormatter={(val) => {
                  if (typeof val === "string" && val.includes(" ")) {
                    return val.split(" ")[1] || val;
                  }
                  return val;
                }}
              />

              <YAxis
                stroke="#64748b"
                tick={{ fill: "#94a3b8", fontSize: 10 }}
                allowDecimals={false}
              />

              <Tooltip content={<CustomTimelineTooltip />} />

              <Area
                type="monotone"
                dataKey="count"
                stroke="#06b6d4"
                strokeWidth={2.5}
                fillOpacity={1}
                fill="url(#campaignDensityGradient)"
                dot={<CustomDot />}
                activeDot={{ r: 7, stroke: "#38bdf8", strokeWidth: 2, fill: "#0284c7" }}
              />

              {/* Reference dots for critical attack spikes */}
              {filteredData
                .filter((d) => d.is_spike)
                .map((d, i) => (
                  <ReferenceDot
                    key={`ref-spike-${i}`}
                    x={d.timestamp}
                    y={d.count}
                    r={6}
                    fill="#ef4444"
                    stroke="#ffffff"
                    strokeWidth={1.5}
                  />
                ))}
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Legend / Footer Indicator */}
      <div className="flex items-center justify-between text-[11px] text-slate-400 border-t border-slate-800/80 pt-2 px-1">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block"></span>
            Normal Baseline
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-400 inline-block"></span>
            Anomaly Timestamp
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block ring-2 ring-rose-500/40"></span>
            Attack Spike Peak
          </span>
        </div>
        <span className="text-[10px] text-slate-500 hidden sm:inline">
          Hover data points for threat breakdown
        </span>
      </div>
    </div>
  );
}

CampaignTimelineChart.propTypes = {
  timelineData: PropTypes.arrayOf(
    PropTypes.shape({
      timestamp: PropTypes.string.isRequired,
      count: PropTypes.number,
      density: PropTypes.number,
      is_spike: PropTypes.bool,
      is_anomaly: PropTypes.bool,
      anomaly_type: PropTypes.string,
    })
  ),
  campaignId: PropTypes.string,
  className: PropTypes.string,
};

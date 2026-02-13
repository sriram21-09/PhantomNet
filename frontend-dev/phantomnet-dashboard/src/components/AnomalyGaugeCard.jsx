import {
  RadialBarChart,
  RadialBar,
  PolarAngleAxis,
  ResponsiveContainer,
} from "recharts";
import "../styles/components/MetricCard.css";

const AnomalyGaugeCard = ({ anomalyScore }) => {
  const percentage = Math.round(anomalyScore * 100);

  const data = [
    {
      name: "Anomaly",
      value: percentage,
    },
  ];

  return (
    <div className="metric-card variant-orange">
      <div className="metric-glow"></div>

      <div className="metric-content">
        <div className="metric-header">
          <span className="metric-title">Anomaly Score</span>
        </div>

        <div style={{ width: "100%", height: 120 }}>
          <ResponsiveContainer width="100%" height="100%">
            <RadialBarChart
              innerRadius="70%"
              outerRadius="100%"
              data={data}
              startAngle={180}
              endAngle={0}
            >
              <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
              <RadialBar
                minAngle={15}
                background
                clockWise
                dataKey="value"
                cornerRadius={10}
              />
            </RadialBarChart>
          </ResponsiveContainer>
        </div>

        <div className="metric-value">
          {percentage}% RISK
        </div>

        <div className="metric-bar">
          <div
            className="metric-bar-fill"
            style={{ width: `${percentage}%` }}
          ></div>
        </div>
      </div>
    </div>
  );
};

export default AnomalyGaugeCard;

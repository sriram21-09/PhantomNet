import React from 'react';
import PropTypes from 'prop-types';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  Cell 
} from 'recharts';

/**
 * FeatureImportanceChart component
 * Visualizes the weights of features using a horizontal bar chart.
 */
const FeatureImportanceChart = ({ data = [], height = 300, className = '' }) => {
  const sortedData = [...data].sort((a, b) => b.value - a.value);

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-slate-900/90 border border-blue-500/20 p-3 rounded-lg backdrop-blur-md shadow-xl">
          <p className="text-white font-bold text-sm mb-1">{label}</p>
          <p className="text-blue-400 text-xs">
            Importance: <span className="font-mono">{(payload[0].value * 100).toFixed(1)}%</span>
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className={`feature-importance-container pro-card p-4 ${className}`} style={{ height }}>
      <h3 className="hud-font text-sm mb-4 text-blue-400 flex items-center gap-2">
        <span className="w-2 h-2 bg-blue-500 rounded-full animate-pulse" />
        Feature Importance
      </h3>
      
      <ResponsiveContainer width="100%" height="80%">
        <BarChart
          layout="vertical"
          data={sortedData}
          margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
          <XAxis 
            type="number" 
            domain={[0, 1]} 
            hide 
          />
          <YAxis 
            dataKey="name" 
            type="category" 
            stroke="#94a3b8" 
            fontSize={11}
            width={120}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(59, 130, 246, 0.1)' }} />
          <Bar 
            dataKey="value" 
            radius={[0, 4, 4, 0]} 
            barSize={12}
          >
            {sortedData.map((entry, index) => (
              <Cell 
                key={`cell-${index}`} 
                fill={`url(#barGradient-${index})`}
                fillOpacity={0.8 + (entry.value * 0.2)}
              />
            ))}
          </Bar>
          
          <defs>
            {sortedData.map((_, index) => (
              <linearGradient key={`gradient-${index}`} id={`barGradient-${index}`} x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.2} />
                <stop offset="100%" stopColor="#22d3ee" stopOpacity={1} />
              </linearGradient>
            ))}
          </defs>
        </BarChart>
      </ResponsiveContainer>

      <div className="mt-2 flex justify-between items-center text-[10px] text-slate-500 uppercase tracking-tighter">
        <span>Low Influence</span>
        <span>High Impact</span>
      </div>

      <style jsx>{`
        .feature-importance-container {
          overflow: visible !important;
        }
      `}</style>
    </div>
  );
};

FeatureImportanceChart.propTypes = {
  data: PropTypes.arrayOf(
    PropTypes.shape({
      name: PropTypes.string.isRequired,
      value: PropTypes.number.isRequired,
    })
  ).isRequired,
  height: PropTypes.oneOfType([PropTypes.number, PropTypes.string]),
  className: PropTypes.string,
};

export default FeatureImportanceChart;

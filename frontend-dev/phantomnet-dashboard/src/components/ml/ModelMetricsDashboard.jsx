import React, { useState, useEffect } from 'react';
import { Activity, Brain, Target, BarChart3, Info } from 'lucide-react';
import ThreatScoreBadge from './ThreatScoreBadge';
import FeatureImportanceChart from './FeatureImportanceChart';

import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip as RechartsTooltip, 
  ResponsiveContainer, 
  AreaChart, 
  Area,
  Cell
} from 'recharts';

/**
 * ModelMetricsDashboard component
 * A comprehensive view of ML model insights and performance.
 */
const ModelMetricsDashboard = () => {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);

  useEffect(() => {
    // Simulate API fetch for ML insights
    const timer = setTimeout(() => {
      setData({
        threatScore: 78,
        modelName: 'NeuralSentinel-X1',
        accuracy: 0.942,
        precision: 0.915,
        recall: 0.892,
        features: [
          { name: 'Packet Entropy', value: 0.82 },
          { name: 'Source Reputation', value: 0.75 },
          { name: 'Port Scanning Index', value: 0.58 },
          { name: 'Geo-Anomaly Score', value: 0.42 },
          { name: 'Burst Duration', value: 0.31 },
          { name: 'Protocol Mismatch', value: 0.15 },
        ],
        predictionDistribution: [
          { x: 0, y: 5 }, { x: 10, y: 15 }, { x: 20, y: 40 }, { x: 30, y: 80 },
          { x: 40, y: 120 }, { x: 50, y: 110 }, { x: 60, y: 160 }, { x: 70, y: 220 },
          { x: 80, y: 350 }, { x: 90, y: 180 }, { x: 100, y: 45 }
        ],
        confidenceHistogram: [
          { range: '0-20%', count: 8 },
          { range: '20-40%', count: 12 },
          { range: '40-60%', count: 25 },
          { range: '60-80%', count: 64 },
          { range: '80-100%', count: 128 },
        ],
        lastTrained: '2026-03-12 14:30',
        activeDetectors: 12,
      });
      setLoading(false);
    }, 1200);

    return () => clearTimeout(timer);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="flex flex-col items-center gap-4">
          <Brain className="w-12 h-12 text-blue-500 animate-bounce" />
          <p className="hud-font text-blue-400 animate-pulse">Initializing ML Engine...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header Info */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-blue-500/10 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Brain className="text-blue-500" />
            ML Insights <span className="text-blue-500/50">Dashboard</span>
          </h1>
          <p className="text-slate-400 text-sm mt-1">Explaining detection logic for current threat landscape</p>
        </div>
        <div className="flex items-center gap-4 bg-slate-900/50 px-4 py-2 rounded-lg border border-white/5">
          <div className="text-right">
            <p className="text-[10px] text-slate-500 uppercase tracking-widest">Model Engine</p>
            <p className="text-sm font-mono text-blue-400">{data.modelName}</p>
          </div>
          <div className="w-[1px] h-8 bg-white/10" />
          <div className="text-right">
            <p className="text-[10px] text-slate-500 uppercase tracking-widest">Last Updated</p>
            <p className="text-sm font-mono text-slate-300">{data.lastTrained}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Threat Overview */}
        <div className="space-y-6">
          <div className="pro-card p-6 flex flex-col items-center justify-center min-h-[280px]">
             <h3 className="hud-font text-xs mb-6 text-slate-400 self-start uppercase tracking-widest flex items-center gap-2">
                <Target size={14} className="text-red-500" /> Current Threat Analysis
             </h3>
             <ThreatScoreBadge score={data.threatScore} size="lg" />
             <div className="mt-8 grid grid-cols-2 gap-4 w-full">
                <div className="text-center p-3 rounded-lg bg-white/5 border border-white/5">
                    <p className="text-[10px] text-slate-500 uppercase">Detectors</p>
                    <p className="text-xl font-bold text-blue-400">{data.activeDetectors}</p>
                </div>
                <div className="text-center p-3 rounded-lg bg-white/5 border border-white/5">
                    <p className="text-[10px] text-slate-500 uppercase">Confidence</p>
                    <p className="text-xl font-bold text-green-400">{(data.accuracy * 100).toFixed(1)}%</p>
                </div>
             </div>
          </div>

          <div className="pro-card p-6">
             <h3 className="hud-font text-xs mb-4 text-slate-400 uppercase tracking-widest flex items-center gap-2">
                <Activity size={14} className="text-blue-400" /> Model Performance
             </h3>
             <div className="space-y-4">
                {[
                    { label: 'Accuracy', value: data.accuracy, color: 'text-blue-400' },
                    { label: 'Precision', value: data.precision, color: 'text-cyan-400' },
                    { label: 'Recall', value: data.recall, color: 'text-indigo-400' },
                ].map((stat) => (
                    <div key={stat.label}>
                        <div className="flex justify-between text-xs mb-1">
                            <span className="text-slate-400">{stat.label}</span>
                            <span className={`font-mono ${stat.color}`}>{(stat.value * 100).toFixed(1)}%</span>
                        </div>
                        <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                            <div 
                                className={`h-full bg-current ${stat.color.replace('text-', 'bg-')}`} 
                                style={{ width: `${stat.value * 100}%`, opacity: 0.6 }} 
                            />
                        </div>
                    </div>
                ))}
             </div>
          </div>
        </div>

        {/* Middle/Right: Charts */}
        <div className="lg:col-span-2 space-y-6">
            <FeatureImportanceChart data={data.features} height={350} />
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="pro-card p-4">
                     <h3 className="hud-font text-xs mb-4 text-slate-400 uppercase tracking-widest flex items-center gap-2">
                        <BarChart3 size={14} className="text-blue-400" /> Prediction Distribution
                    </h3>
                    <div className="h-[200px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={data.predictionDistribution}>
                                <defs>
                                    <linearGradient id="colorY" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                                <XAxis dataKey="x" hide />
                                <YAxis hide />
                                <RechartsTooltip 
                                    contentStyle={{ background: '#0f172a', border: '1px solid rgba(59,130,246,0.2)', fontSize: '10px' }}
                                    itemStyle={{ color: '#3b82f6' }}
                                />
                                <Area type="monotone" dataKey="y" stroke="#3b82f6" fillOpacity={1} fill="url(#colorY)" />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>
                <div className="pro-card p-4">
                     <h3 className="hud-font text-xs mb-4 text-slate-400 uppercase tracking-widest flex items-center gap-2">
                        <Target size={14} className="text-green-400" /> Confidence Histogram
                    </h3>
                    <div className="h-[200px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={data.confidenceHistogram}>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                                <XAxis dataKey="range" fontSize={10} stroke="#64748b" />
                                <YAxis hide />
                                <RechartsTooltip 
                                    contentStyle={{ background: '#0f172a', border: '1px solid rgba(16,185,129,0.2)', fontSize: '10px' }}
                                    itemStyle={{ color: '#10b981' }}
                                />
                                <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>
            
            <div className="pro-card p-4">
                 <h3 className="hud-font text-xs mb-4 text-slate-400 uppercase tracking-widest flex items-center gap-2">
                    <Info size={14} className="text-blue-400" /> Model Summary & Insights
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                    The current model is identifying patterns consistent with high-volume scanning activity targeting the legacy application layer. 
                    The significant impact of "Packet Entropy" combined with "Geo-Anomaly Score" suggests a likely distributed attempt at bypassing location-based access controls.
                </p>
                <div className="mt-4 flex gap-2">
                    <span className="px-2 py-1 bg-red-500/10 text-red-500 border border-red-500/20 rounded text-[9px] uppercase font-bold">Encrypted Attack</span>
                    <span className="px-2 py-1 bg-blue-500/10 text-blue-500 border border-blue-500/20 rounded text-[9px] uppercase font-bold">Scanning</span>
                    <span className="px-2 py-1 bg-purple-500/10 text-purple-500 border border-purple-500/20 rounded text-[9px] uppercase font-bold">Geo-Fencing Bypass</span>
                </div>
            </div>
        </div>
      </div>
    </div>
  );
};


export default ModelMetricsDashboard;

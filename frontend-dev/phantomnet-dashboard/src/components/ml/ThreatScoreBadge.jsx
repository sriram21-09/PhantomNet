import React from 'react';
import PropTypes from 'prop-types';
import { Shield, AlertTriangle, ShieldAlert, ShieldCheck } from 'lucide-react';

/**
 * ThreatScoreBadge component
 * Visualizes a threat score (0-100) with dynamic colors and icons.
 */
const ThreatScoreBadge = ({ score, size = 'md', className = '' }) => {
  const getThreatLevel = (val) => {
    if (val < 25) return { label: 'LOW', color: 'var(--threat-low)', icon: ShieldCheck };
    if (val < 50) return { label: 'MEDIUM', color: 'var(--threat-medium)', icon: Shield };
    if (val < 75) return { label: 'HIGH', color: 'var(--threat-high)', icon: AlertTriangle };
    return { label: 'CRITICAL', color: 'var(--threat-critical)', icon: ShieldAlert };
  };

  const { label, color, icon: Icon } = getThreatLevel(score);
  
  const sizeMap = {
    sm: { circle: 36, stroke: 3, font: '10px', iconSize: 14 },
    md: { circle: 64, stroke: 5, font: '14px', iconSize: 20 },
    lg: { circle: 96, stroke: 8, font: '20px', iconSize: 28 },
  };

  const { circle, stroke, font, iconSize } = sizeMap[size] || sizeMap.md;
  const radius = (circle - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className={`threat-badge-container ${className}`} style={{ '--badge-color': color }}>
      <div className="relative flex items-center justify-center" style={{ width: circle, height: circle }}>
        {/* Background Circle */}
        <svg className="absolute transform -rotate-90" width={circle} height={circle}>
          <circle
            cx={circle / 2}
            cy={circle / 2}
            r={radius}
            fill="transparent"
            stroke="rgba(255, 255, 255, 0.1)"
            strokeWidth={stroke}
          />
          {/* Progress Circle */}
          <circle
            cx={circle / 2}
            cy={circle / 2}
            r={radius}
            fill="transparent"
            stroke={color}
            strokeWidth={stroke}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.5s ease' }}
          />
        </svg>
        
        {/* Center Content */}
        <div className="flex flex-col items-center justify-center z-10">
          <Icon size={iconSize} color={color} className="animate-pulse" />
          <span className="font-bold leading-none" style={{ fontSize: font, color: 'white' }}>
            {score}
          </span>
        </div>
      </div>
      <div className="mt-2 text-center">
        <span className="text-[10px] font-black tracking-widest uppercase opacity-80" style={{ color }}>
          {label}
        </span>
      </div>

      <style jsx>{`
        .threat-badge-container {
          display: inline-flex;
          flex-direction: column;
          align-items: center;
          padding: 1rem;
          background: rgba(15, 23, 42, 0.4);
          border: 1px solid rgba(255, 255, 255, 0.05);
          border-radius: 1rem;
          backdrop-filter: blur(8px);
          box-shadow: 0 0 15px -5px var(--badge-color);
          transition: all 0.3s ease;
        }
        .threat-badge-container:hover {
          transform: scale(1.05);
          box-shadow: 0 0 25px -5px var(--badge-color);
          border-color: rgba(255, 255, 255, 0.1);
        }
      `}</style>
    </div>
  );
};

ThreatScoreBadge.propTypes = {
  score: PropTypes.number.isRequired,
  size: PropTypes.oneOf(['sm', 'md', 'lg']),
  className: PropTypes.string,
};

export default ThreatScoreBadge;

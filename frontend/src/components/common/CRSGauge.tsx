import React from 'react';

interface Props {
  /** Composite Risk Score from 0 to 1. */
  value: number;
}

export const CRSGauge: React.FC<Props> = ({ value }) => {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs text-text.secondary">
        <span>CRS</span>
        <span className="font-mono">{pct.toFixed(1)}%</span>
      </div>
      <div className="w-full h-2 bg-background-border rounded">
        <div className="h-2 bg-severity-high rounded" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
};

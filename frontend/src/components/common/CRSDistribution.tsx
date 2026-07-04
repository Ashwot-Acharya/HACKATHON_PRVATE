import React from 'react';

interface Props {
  /** Buckets of CRS values. */
  data: { label: string; value: number }[];
}

export const CRSDistribution: React.FC<Props> = ({ data }) => {
  return (
    <div className="space-y-2">
      {data.map((b) => (
        <div key={b.label} className="flex items-center gap-3">
          <div className="w-14 text-xs text-text.secondary font-mono">{b.label}</div>
          <div className="flex-1 h-2 bg-background-border rounded">
            <div className="h-2 bg-severity-high rounded" style={{ width: `${Math.min(100, b.value)}%` }} />
          </div>
          <div className="w-10 text-xs text-text.secondary text-right">{b.value}</div>
        </div>
      ))}
    </div>
  );
};

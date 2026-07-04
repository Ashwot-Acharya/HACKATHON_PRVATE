import React from 'react';

interface Props {
  /** Top contributing features. */
  features: { name: string; value: number }[];
  /** Summary text. */
  summary: string;
}

export const SHAPSummary: React.FC<Props> = ({ features, summary }) => {
  return (
    <div className="space-y-3">
      <div className="space-y-2">
        {features.map((f) => (
          <div key={f.name} className="flex items-center gap-3">
            <div className="w-36 text-xs text-text.secondary">{f.name}</div>
            <div className="flex-1 h-2 bg-background-border rounded">
              <div className="h-2 bg-challenge-c1 rounded" style={{ width: `${Math.min(100, Math.abs(f.value) * 100)}%` }} />
            </div>
            <div className="w-10 text-xs text-text.secondary text-right">{f.value.toFixed(2)}</div>
          </div>
        ))}
      </div>
      <div className="text-xs text-text.secondary">{summary}</div>
    </div>
  );
};

import React from 'react';

interface Feature {
  name: string;
  value: number;
}

interface Props {
  features: Feature[];
  summary: string;
}

export const SHAPExplanation: React.FC<Props> = ({ features, summary }) => (
  <div className="space-y-3">
    {features.map((f, i) => {
      const isPositive = f.value > 0;
      const width = Math.min(Math.abs(f.value) * 100, 100);
      return (
        <div key={f.name} className="animate-fade-up" style={{ animationDelay: `${i * 80}ms` }}>
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-text-secondary">{f.name}</span>
            <span className={`text-xs font-mono ${isPositive ? 'text-severity-high' : 'text-severity-low'}`}>
              {isPositive ? '+' : ''}{f.value.toFixed(2)}
            </span>
          </div>
          <div className="progress-bar">
            <div
              className={`progress-bar-fill ${isPositive ? 'bg-gradient-to-r from-severity-medium to-severity-high' : 'bg-gradient-to-r from-severity-low to-challenge-c1'}`}
              style={{ width: `${width}%` }}
            />
          </div>
        </div>
      );
    })}
    <p className="text-[10px] text-text-muted leading-relaxed mt-2">{summary}</p>
  </div>
);

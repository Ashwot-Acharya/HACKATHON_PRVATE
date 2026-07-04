import React from 'react';

interface Props {
  label: string;
  since: string;
  fpr: string;
}

export const RegimeContextBadge: React.FC<Props> = ({ label, since, fpr }) => (
  <div className="glass-panel p-4 glow-c2">
    <div className="flex items-center justify-between mb-2">
      <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">Regime Context</span>
      <span className="challenge-badge challenge-badge-c2">C2</span>
    </div>
    <div className="text-sm font-semibold text-challenge-c2 mb-1">{label}</div>
    <div className="flex items-center gap-4 text-[10px] text-text-muted">
      <span>Since: {since}</span>
      <span>FPR: {fpr}</span>
    </div>
  </div>
);

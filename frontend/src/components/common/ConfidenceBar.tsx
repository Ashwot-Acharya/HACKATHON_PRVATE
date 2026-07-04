import React from 'react';

interface Props {
  /** Confidence score from 0 to 1. */
  value: number;
}

export const ConfidenceBar: React.FC<Props> = ({ value }) => {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  return (
    <div className="w-full h-2 bg-background-border rounded">
      <div className="h-2 bg-challenge-c2 rounded" style={{ width: `${pct}%` }} />
    </div>
  );
};

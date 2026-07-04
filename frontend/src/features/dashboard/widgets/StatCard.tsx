import React from 'react';

interface Props {
  /** Card title. */
  title: string;
  /** Main value. */
  value: string;
  /** Optional caption. */
  caption?: string;
}

export const StatCard: React.FC<Props> = ({ title, value, caption }) => {
  return (
    <div className="bg-panel border border-background-border rounded p-4">
      <div className="text-xs text-text.secondary">{title}</div>
      <div className="text-lg text-text.primary font-semibold mt-1">{value}</div>
      {caption && <div className="text-xs text-text.secondary mt-1">{caption}</div>}
    </div>
  );
};

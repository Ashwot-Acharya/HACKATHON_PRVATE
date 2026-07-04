import React from 'react';

interface Props {
  /** Label text. */
  label: string;
  /** Value text. */
  value: string;
}

export const InfoPill: React.FC<Props> = ({ label, value }) => {
  return (
    <div className="px-3 py-1 rounded bg-background-border text-xs text-text.secondary">
      <span className="font-semibold text-text.primary mr-1">{label}</span>{value}
    </div>
  );
};

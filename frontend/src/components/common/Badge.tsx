import React from 'react';

interface Props {
  /** Badge text. */
  text: string;
  /** Optional color class. */
  colorClass?: string;
}

export const Badge: React.FC<Props> = ({ text, colorClass }) => {
  return <span className={`px-2 py-0.5 rounded text-xs ${colorClass ?? 'bg-background-border text-text.secondary'}`}>{text}</span>;
};

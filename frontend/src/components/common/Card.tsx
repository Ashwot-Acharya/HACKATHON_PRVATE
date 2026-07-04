import React from 'react';

interface Props {
  /** Content to render inside. */
  children: React.ReactNode;
  /** Optional className overrides. */
  className?: string;
}

export const Card: React.FC<Props> = ({ children, className }) => {
  return <div className={`bg-panel border border-background-border rounded p-4 ${className ?? ''}`}>{children}</div>;
};

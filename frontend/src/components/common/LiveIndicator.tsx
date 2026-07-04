import React from 'react';

interface Props {
  /** Whether the indicator is live. */
  isLive: boolean;
}

export const LiveIndicator: React.FC<Props> = ({ isLive }) => {
  return (
    <span className={`inline-flex items-center gap-2 text-xs ${isLive ? 'text-severity-low' : 'text-text.muted'}`}>
      <span className={`w-2 h-2 rounded-full ${isLive ? 'bg-severity-low animate-pulse' : 'bg-background-border'}`} />
      {isLive ? 'LIVE' : 'STALE'}
    </span>
  );
};

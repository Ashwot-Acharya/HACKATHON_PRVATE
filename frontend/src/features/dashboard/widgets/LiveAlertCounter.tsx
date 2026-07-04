import React from 'react';

interface Props {
  /** Active alert count. */
  count: number;
}

export const LiveAlertCounter: React.FC<Props> = ({ count }) => {
  return (
    <div className="bg-panel border border-background-border rounded p-4">
      <div className="text-xs text-text.secondary">Live Alerts</div>
      <div className="text-lg text-text.primary font-semibold mt-1">{count}</div>
    </div>
  );
};

import React from 'react';
import { ChallengeBadge } from '@components/common/ChallengeBadge';

interface ConsoleEvent {
  id: string;
  time: string;
  message: string;
  challenge?: 'C1' | 'C2' | 'C3' | 'C4';
}

interface Props {
  /** Event log entries. */
  events: ConsoleEvent[];
  /** Whether scenario is running. */
  isRunning: boolean;
  /** Stop callback. */
  onStop?: () => void;
}

export const RedTeamConsole: React.FC<Props> = ({ events, isRunning, onStop }) => {
  return (
    <div className="bg-panel border border-background-border rounded p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="text-sm font-semibold text-text.primary">Red Team Console</div>
        {isRunning && <button onClick={onStop} className="px-3 py-1 rounded bg-severity-critical text-white text-xs">Stop Scenario</button>}
      </div>
      <div className="space-y-2 max-h-64 overflow-auto">
        {events.map((e) => (
          <div key={e.id} className="p-2 bg-background-border rounded">
            <div className="flex items-center justify-between text-xs text-text.secondary">
              <span>{e.time}</span>
              {e.challenge && <ChallengeBadge challenge={e.challenge} />}
            </div>
            <div className="text-sm text-text.primary mt-1">{e.message}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

import React from 'react';
import { ChallengeBadge } from '@components/common/ChallengeBadge';

interface Props {
  /** Map of challenge to status text. */
  status: { challenge: 'C1' | 'C2' | 'C3' | 'C4'; text: string }[];
}

export const ChallengeStatusGrid: React.FC<Props> = ({ status }) => {
  return (
    <div className="grid grid-cols-2 gap-2">
      {status.map((s) => (
        <div key={s.challenge} className="bg-panel border border-background-border rounded p-3">
          <div className="flex items-center justify-between">
            <div className="text-xs text-text.secondary">Challenge {s.challenge}</div>
            <ChallengeBadge challenge={s.challenge} />
          </div>
          <div className="text-sm text-text.primary mt-2">{s.text}</div>
        </div>
      ))}
    </div>
  );
};

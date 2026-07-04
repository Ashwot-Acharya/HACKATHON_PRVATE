import React from 'react';
import type { IntelFeedStatus } from '@/types/intel.types';
import { LiveIndicator } from '@components/common/LiveIndicator';

interface Props {
  /** Intel feed list. */
  feeds: IntelFeedStatus[];
}

export const ThreatIntelFeed: React.FC<Props> = ({ feeds }) => {
  return (
    <div className="bg-panel border border-background-border rounded p-4">
      <div className="text-sm font-semibold text-text.primary mb-3">Threat Intel Feeds</div>
      <div className="space-y-2">
        {feeds.map((f) => (
          <div key={f.name} className="flex items-center justify-between text-sm">
            <div>
              <div className="text-text.primary">{f.name}</div>
              <div className="text-xs text-text.secondary">{f.count} records</div>
            </div>
            <LiveIndicator isLive={f.status === 'LIVE'} />
          </div>
        ))}
      </div>
    </div>
  );
};

import React from 'react';
import { Badge } from '@components/common/Badge';
import { TimestampDisplay } from '@components/common/TimestampDisplay';

interface TimelineItem {
  id: string;
  timestamp: string;
  title: string;
  technique?: string;
  challenge?: 'C1' | 'C2' | 'C3' | 'C4';
}

interface Props {
  /** Timeline events in chronological order. */
  items: TimelineItem[];
}

export const IncidentTimeline: React.FC<Props> = ({ items }) => {
  return (
    <div className="space-y-3">
      {items.map((item) => (
        <div key={item.id} className="flex gap-3">
          <div className="w-2 h-2 mt-2 rounded-full bg-challenge-c1" />
          <div className="flex-1 bg-panel border border-background-border rounded p-3">
            <div className="flex items-center justify-between">
              <div className="text-text.primary text-sm font-semibold">{item.title}</div>
              {item.challenge && <Badge text={item.challenge} colorClass="bg-background-border text-text.secondary" />}
            </div>
            <div className="mt-1 text-xs text-text.secondary flex items-center gap-2">
              <TimestampDisplay value={item.timestamp} />
              {item.technique && <span className="font-mono">{item.technique}</span>}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

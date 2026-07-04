import React from 'react';
import { SeverityIndicator } from '@components/common/SeverityIndicator';

interface Props {
  /** Incident id. */
  id: string;
  /** Title text. */
  title: string;
  /** Severity. */
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'QUEUED';
}

export const IncidentHeader: React.FC<Props> = ({ id, title, severity }) => {
  return (
    <div className="bg-panel border border-background-border rounded p-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-text.secondary">{id}</div>
          <div className="text-text.primary font-semibold">{title}</div>
        </div>
        <SeverityIndicator severity={severity} />
      </div>
    </div>
  );
};

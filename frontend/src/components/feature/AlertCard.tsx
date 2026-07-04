import React from 'react';
import type { Alert } from '@/types/alert.types';
import { SeverityIndicator } from '@components/common/SeverityIndicator';
import { MITRETag } from '@components/common/MITRETag';
import { ConfidenceBar } from '@components/common/ConfidenceBar';
import { TimestampDisplay } from '@components/common/TimestampDisplay';

interface Props {
  /** Alert payload. */
  alert: Alert;
  /** Optional click handler. */
  onAlertClick?: (id: string) => void;
}

export const AlertCard: React.FC<Props> = ({ alert, onAlertClick }) => {
  return (
    <button
      type="button"
      onClick={() => onAlertClick?.(alert.id)}
      className="w-full text-left p-3 rounded bg-background-border hover:bg-background-elevated transition"
    >
      <div className="flex items-center justify-between">
        <div className="text-text.primary font-semibold">{alert.id}</div>
        <SeverityIndicator severity={alert.severity} />
      </div>
      <div className="mt-2 flex items-center gap-3 text-xs text-text.secondary">
        <TimestampDisplay value={alert.timestamp} />
        <MITRETag technique={alert.mitre} severity={alert.severity} />
        <span className="font-mono">{alert.sourceIp}</span>
      </div>
      <div className="mt-2">
        <ConfidenceBar value={alert.crs} />
      </div>
    </button>
  );
};

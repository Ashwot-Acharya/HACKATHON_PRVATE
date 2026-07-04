import React from 'react';

interface Props {
  /** Severity label (CRITICAL/HIGH/MEDIUM/LOW). */
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'QUEUED' | 'INFO';
}

const severityStyles: Record<Props['severity'], string> = {
  CRITICAL: 'bg-severity-critical text-white',
  HIGH: 'bg-severity-high text-white',
  MEDIUM: 'bg-severity-medium text-black',
  LOW: 'bg-severity-low text-black',
  QUEUED: 'bg-background-border text-text.secondary',
  INFO: 'bg-[#027373]/20 text-[#11D9C5]'
};

export const SeverityIndicator: React.FC<Props> = ({ severity }) => {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${severityStyles[severity]}`}>
      {severity}
    </span>
  );
};

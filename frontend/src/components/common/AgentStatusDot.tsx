import React from 'react';

interface Props {
  /** Agent status. */
  status: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
}

const statusColor: Record<Props['status'], string> = {
  ONLINE: 'bg-severity-low',
  DEGRADED: 'bg-severity-medium',
  OFFLINE: 'bg-severity-critical'
};

export const AgentStatusDot: React.FC<Props> = ({ status }) => {
  return <span className={`inline-block w-2 h-2 rounded-full ${statusColor[status]}`} aria-label={status} />;
};

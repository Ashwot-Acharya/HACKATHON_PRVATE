import React from 'react';
import type { ComplianceStatus } from '@/types/compliance.types';

interface Props {
  /** Compliance status. */
  status: ComplianceStatus;
}

export const ComplianceSummary: React.FC<Props> = ({ status }) => {
  const items = [
    { label: 'PCI-DSS', value: status.pci },
    { label: 'SOX', value: status.sox },
    { label: 'GDPR', value: status.gdpr }
  ];

  return (
    <div className="bg-panel border border-background-border rounded p-4">
      <div className="text-sm font-semibold text-text.primary mb-3">Compliance Summary</div>
      <div className="grid grid-cols-3 gap-3">
        {items.map((i) => (
          <div key={i.label} className="p-3 bg-background-border rounded">
            <div className="text-xs text-text.secondary">{i.label}</div>
            <div className="text-sm text-text.primary mt-1">{i.value.status}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

import React from 'react';

interface Props {
  /** Primary message to show. */
  title: string;
  /** Optional supporting description. */
  description?: string;
}

export const EmptyState: React.FC<Props> = ({ title, description }) => {
  return (
    <div className="p-6 rounded bg-panel text-center">
      <div className="text-text.primary font-semibold">{title}</div>
      {description && <div className="text-text.secondary mt-2 text-sm">{description}</div>}
    </div>
  );
};

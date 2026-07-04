import React from 'react';

interface Props {
  /** Page title. */
  title: string;
  /** Optional subtitle. */
  subtitle?: string;
}

export const PageHeader: React.FC<Props> = ({ title, subtitle }) => {
  return (
    <div className="mb-4">
      <h1 className="text-xl text-text.primary font-semibold">{title}</h1>
      {subtitle && <div className="text-sm text-text.secondary mt-1">{subtitle}</div>}
    </div>
  );
};

import React from 'react';

interface Props {
  /** Title text. */
  title: string;
  /** Optional right-side element. */
  action?: React.ReactNode;
}

export const SectionHeader: React.FC<Props> = ({ title, action }) => {
  return (
    <div className="flex items-center justify-between">
      <h3 className="text-text.primary text-sm font-semibold tracking-wide">{title}</h3>
      {action}
    </div>
  );
};

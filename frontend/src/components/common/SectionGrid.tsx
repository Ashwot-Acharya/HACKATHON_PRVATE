import React from 'react';

interface Props {
  /** Content to render. */
  children: React.ReactNode;
}

export const SectionGrid: React.FC<Props> = ({ children }) => {
  return <div className="grid gap-4 lg:grid-cols-3">{children}</div>;
};

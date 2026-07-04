import React from 'react';

export const LoadingSpinner: React.FC = () => {
  return (
    <div className="inline-flex items-center gap-2 text-text.secondary">
      <span className="w-4 h-4 rounded-full border-2 border-background-border border-t-text.primary animate-spin" />
      Loading
    </div>
  );
};

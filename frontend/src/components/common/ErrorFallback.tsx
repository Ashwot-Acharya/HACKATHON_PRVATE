import React from 'react';

export const ErrorFallback: React.FC<{ resetErrorBoundary: () => void }> = ({ resetErrorBoundary }) => {
  return (
    <div role="alert" className="p-4 bg-panel rounded">
      <h3 className="text-text.primary">Something went wrong</h3>
      <div className="text-text.secondary mt-2">An unexpected error occurred. Try refreshing the page.</div>
      <button onClick={resetErrorBoundary} className="mt-4 px-3 py-2 bg-challenge-c3 text-white rounded">Refresh</button>
    </div>
  );
};

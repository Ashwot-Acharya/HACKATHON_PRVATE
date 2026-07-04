import React from 'react';
import { Badge } from '@components/common/Badge';

interface Props {
  /** Active filter count. */
  count: number;
  /** Clear filters callback. */
  onClear: () => void;
}

export const AlertFilters: React.FC<Props> = ({ count, onClear }) => {
  return (
    <div className="bg-panel border border-background-border rounded p-4">
      <div className="flex items-center justify-between">
        <div className="text-sm font-semibold text-text.primary">Filters</div>
        {count > 0 && <Badge text={`${count} active`} />}
      </div>
      <div className="mt-3 text-xs text-text.secondary">Filter controls will appear here.</div>
      {count > 0 && (
        <button onClick={onClear} className="mt-3 px-3 py-1 rounded bg-background-elevated text-text.primary text-xs">Clear all</button>
      )}
    </div>
  );
};

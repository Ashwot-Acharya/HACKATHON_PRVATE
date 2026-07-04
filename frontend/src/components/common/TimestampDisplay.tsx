import React from 'react';
import { formatDistanceToNow } from 'date-fns';

interface Props {
  /** ISO timestamp. */
  value: string;
}

export const TimestampDisplay: React.FC<Props> = ({ value }) => {
  return (
    <span className="text-xs text-text.secondary">
      {formatDistanceToNow(new Date(value), { addSuffix: true })}
    </span>
  );
};

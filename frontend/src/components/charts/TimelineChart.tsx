import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine } from 'recharts';

interface Props {
  /** Chart data: label + value. */
  data: { label: string; value: number }[];
  /** Optional threshold line. */
  threshold?: number;
}

export const TimelineChart: React.FC<Props> = ({ data, threshold }) => {
  return (
    <div className="h-48">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <XAxis dataKey="label" stroke="#9BA4C4" fontSize={10} />
          <YAxis stroke="#9BA4C4" fontSize={10} />
          <Tooltip />
          {typeof threshold === 'number' && (
            <ReferenceLine y={threshold} stroke="#EF4444" strokeDasharray="4 4" />
          )}
          <Line type="monotone" dataKey="value" stroke="#8B5CF6" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

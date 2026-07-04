import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

interface Props {
  /** Chart data: label + value. */
  data: { label: string; value: number }[];
}

export const DetectionRateChart: React.FC<Props> = ({ data }) => {
  return (
    <div className="h-40">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <XAxis dataKey="label" stroke="#9BA4C4" fontSize={10} />
          <YAxis stroke="#9BA4C4" fontSize={10} />
          <Tooltip />
          <Line type="monotone" dataKey="value" stroke="#14B8A6" strokeWidth={2} dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

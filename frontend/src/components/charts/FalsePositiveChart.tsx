import React from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

interface Props {
  /** Chart data: label + value. */
  data: { label: string; value: number }[];
}

export const FalsePositiveChart: React.FC<Props> = ({ data }) => {
  return (
    <div className="h-40">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data}>
          <XAxis dataKey="label" stroke="#9BA4C4" fontSize={10} />
          <YAxis stroke="#9BA4C4" fontSize={10} />
          <Tooltip />
          <Area type="monotone" dataKey="value" stroke="#F59E0B" fill="#F59E0B" fillOpacity={0.3} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

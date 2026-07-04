import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

interface Props {
  /** Chart data: label + value. */
  data: { label: string; value: number }[];
}

export const AlertVolumeChart: React.FC<Props> = ({ data }) => {
  return (
    <div className="h-40">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data}>
          <XAxis dataKey="label" stroke="#9BA4C4" fontSize={10} />
          <YAxis stroke="#9BA4C4" fontSize={10} />
          <Tooltip />
          <Bar dataKey="value" fill="#8B5CF6" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

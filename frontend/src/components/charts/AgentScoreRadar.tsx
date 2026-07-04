import React from 'react';
import { RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer } from 'recharts';

interface Props {
  /** Radar data: name + value. */
  data: { name: string; value: number }[];
}

export const AgentScoreRadar: React.FC<Props> = ({ data }) => {
  return (
    <div className="h-48">
      <ResponsiveContainer width="100%" height="100%">
        <RadarChart data={data}>
          <PolarGrid stroke="#252839" />
          <PolarAngleAxis dataKey="name" tick={{ fill: '#9BA4C4', fontSize: 10 }} />
          <Radar dataKey="value" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.35} />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  );
};

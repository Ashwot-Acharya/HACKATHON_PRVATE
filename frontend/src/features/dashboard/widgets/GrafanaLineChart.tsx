import React from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

interface TimeSeriesData {
  time: string;
  value: number;
}

interface GrafanaLineChartProps {
  title: string;
  data: TimeSeriesData[];
  color?: string;
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0];
    return (
      <div className="bg-bg-panel border border-bg-border px-3 py-2 text-xs rounded text-text-primary shadow-lg">
        <div className="text-text-secondary mb-1">{label}</div>
        <div>
          <span style={{ color: data.color }} className="mr-2">●</span>
          <span className="mr-4 text-text-secondary">Count</span>
          <span className="font-bold">{data.value}</span>
        </div>
      </div>
    );
  }
  return null;
};

export const GrafanaLineChart: React.FC<GrafanaLineChartProps> = ({ 
  title, 
  data,
  color = '#73BF69' // Default green
}) => {
  return (
    <div className="bg-bg-panel border border-bg-border rounded-lg shadow-sm flex flex-col h-full relative group">
      {/* Title */}
      <div className="p-3 pb-0 flex items-center justify-between z-10">
        <span className="text-[12px] font-semibold text-text-secondary tracking-wide uppercase truncate" title={title}>
          {title}
        </span>
      </div>

      <div className="flex-1 w-full min-h-[150px] p-2 pt-4">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={data}
            margin={{ top: 0, right: 0, left: -20, bottom: 0 }}
          >
            <defs>
              <linearGradient id={`colorValue-${title.replace(/\s+/g, '')}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={color} stopOpacity={0.3}/>
                <stop offset="95%" stopColor={color} stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" vertical={false} />
            <XAxis 
              dataKey="time" 
              axisLine={false} 
              tickLine={false} 
              tick={{ fill: '#6B7280', fontSize: 10 }}
              minTickGap={20}
            />
            <YAxis 
              axisLine={false} 
              tickLine={false} 
              tick={{ fill: '#6B7280', fontSize: 10 }} 
            />
            <Tooltip content={<CustomTooltip />} />
            <Area 
              type="monotone" 
              dataKey="value" 
              stroke={color} 
              strokeWidth={2}
              fillOpacity={1} 
              fill={`url(#colorValue-${title.replace(/\s+/g, '')})`} 
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

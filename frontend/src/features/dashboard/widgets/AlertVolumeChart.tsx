import React, { useEffect, useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend } from 'recharts';
import { apiClient } from '@lib/axios';

interface VolumeData {
  time: number;
  raw: number;
  correlated: number;
}

export const AlertVolumeChart: React.FC = () => {
  const [data, setData] = useState<VolumeData[]>([]);

  useEffect(() => {
    const fetchVolume = async () => {
      try {
        const res = await apiClient.get('/pipeline/metrics/volume');
        const rawSeries = res.data.raw;
        const corrSeries = res.data.correlated;
        
        // Merge the two series
        const merged = rawSeries.map((r: any, i: number) => {
          const d = new Date(r.time);
          const timeStr = `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
          return {
            time: timeStr,
            raw: r.value,
            correlated: corrSeries[i]?.value || 0
          };
        });
        setData(merged);
      } catch (e) {
        console.error("Failed to fetch volume data", e);
      }
    };
    fetchVolume();
    const interval = setInterval(fetchVolume, 5000);
    return () => clearInterval(interval);
  }, []);

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-bg-panel border border-bg-border px-3 py-2 text-xs rounded text-text-primary shadow-lg">
          <div className="text-text-secondary mb-1">{label}</div>
          {payload.map((p: any, i: number) => (
            <div key={i} className="flex items-center gap-2">
              <span style={{ color: p.color }}>●</span>
              <span className="text-text-secondary capitalize">{p.name}</span>
              <span className="font-bold">{p.value}</span>
            </div>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div className="bg-bg-panel border border-bg-border rounded-lg shadow-sm flex flex-col h-full relative group p-4">
      <h3 className="text-sm font-semibold text-text-primary mb-2">Alert volume — raw vs correlated</h3>
      <div className="flex-1 w-full min-h-[200px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="colorRaw" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#EF4444" stopOpacity={0.1}/>
                <stop offset="95%" stopColor="#EF4444" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorCorr" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.1}/>
                <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" vertical={false} opacity={0.2} />
            <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: '#6B7280', fontSize: 10 }} minTickGap={30} />
            <YAxis axisLine={false} tickLine={false} tick={{ fill: '#6B7280', fontSize: 10 }} />
            <Tooltip content={<CustomTooltip />} />
            <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} iconType="rect" iconSize={8} />
            <Area type="monotone" name="Raw" dataKey="raw" stroke="#EF4444" strokeWidth={2} fillOpacity={1} fill="url(#colorRaw)" isAnimationActive={false} />
            <Area type="monotone" name="Correlated" dataKey="correlated" stroke="#3B82F6" strokeWidth={2} fillOpacity={1} fill="url(#colorCorr)" isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

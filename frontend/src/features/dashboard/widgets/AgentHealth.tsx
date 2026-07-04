import React, { useEffect, useState } from 'react';
import { apiClient } from '@lib/axios';

interface Latencies {
  packet: number;
  flow: number;
  behavior: number;
  correlation: number;
  response: number;
}

export const AgentHealth: React.FC = () => {
  const [latencies, setLatencies] = useState<Latencies>({
    packet: 0,
    flow: 0,
    behavior: 0,
    correlation: 0,
    response: 0,
  });

  useEffect(() => {
    const fetchLatencies = async () => {
      try {
        const res = await apiClient.get('/pipeline/metrics/latencies');
        setLatencies(res.data);
      } catch (e) {
        console.error("Failed to fetch latencies", e);
      }
    };
    fetchLatencies();
    const interval = setInterval(fetchLatencies, 2000);
    return () => clearInterval(interval);
  }, []);

  const agents = [
    { name: 'Packet agent', key: 'packet' },
    { name: 'Flow agent', key: 'flow' },
    { name: 'Behavior agent', key: 'behavior' },
    { name: 'Correlation agent', key: 'correlation' },
    { name: 'Response agent', key: 'response' },
  ];

  const getColor = (ms: number) => {
    if (ms === 0) return 'text-text-muted'; // inactive
    if (ms < 15) return 'text-[#11D9C5]'; // green
    if (ms < 40) return 'text-severity-medium'; // yellow/orange
    return 'text-severity-critical'; // red
  };

  return (
    <div className="bg-panel border border-background-border rounded-lg p-4 h-full flex flex-col">
      <h3 className="text-sm font-semibold text-text-primary mb-3">Agent health</h3>
      <div className="space-y-2 flex-1 justify-center flex flex-col gap-1">
        {agents.map((agent) => {
          const val = latencies[agent.key as keyof Latencies] || 0;
          return (
            <div key={agent.key} className="flex justify-between items-center text-xs p-1">
              <span className="text-text-secondary">{agent.name}</span>
              <div className="flex items-center gap-1.5 font-mono">
                <span className={`w-1.5 h-1.5 rounded-full ${val > 0 ? (val < 15 ? 'bg-[#11D9C5]' : val < 40 ? 'bg-severity-medium' : 'bg-severity-critical') : 'bg-text-muted'}`} />
                <span className={getColor(val)}>{val > 0 ? `${val.toFixed(0)}ms` : 'idle'}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { agentsService } from '@services/agents.service';
import { queryKeys } from '@lib/queryKeys';
import { Cpu } from 'lucide-react';

const challengeMap: Record<string, string> = {
  packet: 'C4',
  flow: 'C2',
  behavior: 'C1',
  correlation: 'C3',
  response: '—',
};

const challengeBadge: Record<string, string> = {
  C1: 'challenge-badge-c1',
  C2: 'challenge-badge-c2',
  C3: 'challenge-badge-c3',
  C4: 'challenge-badge-c4',
};

export const AgentHealthPanel: React.FC = () => {
  const { data: agents } = useQuery({
    queryKey: queryKeys.agents.health,
    queryFn: agentsService.getHealth,
    refetchInterval: 10000,
  });

  return (
    <div className="glass-panel p-3">
      <div className="flex items-center gap-2 mb-2 px-1">
        <Cpu size={12} className="text-text-muted" />
        <span className="text-[10px] text-text-muted uppercase tracking-wider font-semibold">Agent Pipeline Health</span>
      </div>
      <div className="flex items-center gap-3">
        {(agents ?? [
          { id: 'packet', name: 'Packet Agent', status: 'LOADING', eps: 0 },
          { id: 'flow', name: 'Flow Agent', status: 'LOADING', eps: 0 },
          { id: 'behavior', name: 'Behavior Agent', status: 'LOADING', eps: 0 },
          { id: 'correlation', name: 'Correlation Agent', status: 'LOADING', eps: 0 },
          { id: 'response', name: 'Response Agent', status: 'LOADING', eps: 0 },
        ]).map((agent: any, i: number) => { // eslint-disable-line @typescript-eslint/no-explicit-any
          const challenge = challengeMap[agent.id] || '—';
          const isOnline = agent.status === 'ONLINE';
          return (
            <div
              key={agent.id}
              className={`flex-1 p-2.5 rounded-lg border transition-all ${
                isOnline
                  ? 'bg-background-elevated border-background-border hover:border-challenge-c4/30'
                  : 'bg-background-primary border-background-border opacity-50'
              } animate-fade-up`}
              style={{ animationDelay: `${i * 60}ms` }}
            >
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-1.5">
                  <div className={isOnline ? 'status-dot-online' : agent.status === 'LOADING' ? 'shimmer w-2 h-2 rounded-full' : 'status-dot-offline'} />
                  <span className="text-[10px] font-semibold text-text-primary truncate">{agent.name}</span>
                </div>
                {challenge !== '—' && (
                  <span className={`challenge-badge ${challengeBadge[challenge]}`} style={{ fontSize: '8px', padding: '0 3px' }}>
                    {challenge}
                  </span>
                )}
              </div>
              {isOnline && (
                <div className="text-[10px] text-text-muted font-mono">{agent.eps || '—'} EPS</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

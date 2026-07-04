import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { agentsService } from '@services/agents.service';
import { Settings, Server } from 'lucide-react';
import { queryKeys } from '@lib/queryKeys';

const SettingsPage: React.FC = () => {
  const { data: agents } = useQuery({
    queryKey: queryKeys.agents.health,
    queryFn: agentsService.getHealth,
  });

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6 animate-fade-up">
      <div className="flex items-center gap-3 mb-8">
        <div className="w-10 h-10 rounded-lg bg-bg-panel border border-bg-border flex items-center justify-center">
          <Settings size={20} className="text-text-primary" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-text-primary">System Settings</h1>
          <p className="text-sm text-text-muted">BankSentinel IDS agent status and system information</p>
        </div>
      </div>

      {/* Agent Status */}
      <div className="bg-bg-panel border border-bg-border rounded-xl shadow-sm p-5">
        <h2 className="text-sm font-semibold text-text-primary mb-4 flex items-center gap-2">
          <Server size={16} /> Agent Status
        </h2>
        <div className="space-y-3">
          {(agents ?? []).map((agent: Record<string, unknown>) => (
            <div key={agent.id as string} className="flex items-center justify-between p-3 rounded-lg bg-bg-elevated border border-bg-border">
              <div className="flex items-center gap-3">
                <div className={`w-2.5 h-2.5 rounded-full ${(agent.status as string) === 'ONLINE' ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-sm font-medium text-text-primary">{agent.name as string}</span>
              </div>
              <div className="flex items-center gap-4">
                <span className="text-xs text-text-muted font-mono">{(agent.eps as number) || 0} EPS</span>
                <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                  (agent.status as string) === 'ONLINE'
                    ? 'bg-green-100 text-green-700'
                    : 'bg-red-100 text-red-700'
                }`}>
                  {agent.status as string}
                </span>
              </div>
            </div>
          ))}
          {(!agents || agents.length === 0) && (
            <div className="text-center py-4 text-text-muted text-sm">No agent data available.</div>
          )}
        </div>
      </div>

      {/* System Info */}
      <div className="bg-bg-panel border border-bg-border rounded-xl shadow-sm p-5">
        <h2 className="text-sm font-semibold text-text-primary mb-4">System Information</h2>
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div className="p-3 rounded-lg bg-bg-elevated">
            <div className="text-[10px] text-text-muted uppercase mb-1">Backend</div>
            <div className="text-text-primary font-mono text-xs">FastAPI / Uvicorn</div>
          </div>
          <div className="p-3 rounded-lg bg-bg-elevated">
            <div className="text-[10px] text-text-muted uppercase mb-1">ML Engine</div>
            <div className="text-text-primary font-mono text-xs">XGBoost + LSTM</div>
          </div>
          <div className="p-3 rounded-lg bg-bg-elevated">
            <div className="text-[10px] text-text-muted uppercase mb-1">Network Capture</div>
            <div className="text-text-primary font-mono text-xs">Suricata EVE JSON</div>
          </div>
          <div className="p-3 rounded-lg bg-bg-elevated">
            <div className="text-[10px] text-text-muted uppercase mb-1">Audit Chain</div>
            <div className="text-text-primary font-mono text-xs">SHA-256 Immutable</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SettingsPage;

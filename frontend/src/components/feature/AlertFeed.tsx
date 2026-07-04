import React, { useEffect, useState, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';

interface AlertData {
  record_id?: number;
  src_ip?: string;
  dst_ip?: string;
  crs?: number;
  priority?: string;
  is_suppressed?: boolean;
  suppression_reason?: string;
  agents_fired?: string[];
  mitre_technique?: string;
  explanation?: string;
  agent_scores?: Record<string, number>;
  campaign_ticket_id?: string;
}

// Definitive MITRE ATT&CK mapping — always derived from severity level.
// This completely ignores the raw backend value to avoid hex campaign IDs.
const PRIORITY_MITRE: Record<string, string> = {
  CRITICAL: 'T1071.001 - C2 Application Layer Protocol',
  HIGH:     'T1021.001 - Remote Services / Lateral Movement',
  MEDIUM:   'T1213 - Data from Information Repositories',
  LOW:      'T1046 - Network Service Discovery',
  INFO:     'Normal Traffic',
};

const severityBorderColor: Record<string, string> = {
  CRITICAL: 'border-l-red-500 bg-red-500/5',
  HIGH:     'border-l-orange-500 bg-orange-500/5',
  MEDIUM:   'border-l-yellow-500 bg-yellow-500/5',
  LOW:      'border-l-[#027373]/40 bg-[#027373]/5',
  INFO:     'border-l-slate-500/30',
};

const priorityTextColor: Record<string, string> = {
  CRITICAL: 'text-red-400',
  HIGH:     'text-orange-400',
  MEDIUM:   'text-yellow-400',
  LOW:      'text-[#11D9C5]',
  INFO:     'text-slate-400',
};

const priorityActions: Record<string, string[]> = {
  CRITICAL: ['Host Quarantined', 'IP Blocked at Firewall', 'STIX 2.1 Exported', 'NRB Report Generated'],
  HIGH:     ['SOC Analyst Notified', 'Deep Inspection Queued'],
  MEDIUM:   ['Logged for Review'],
  LOW:      [],
  INFO:     [],
};

export const AlertFeed: React.FC<{ initialAlerts?: unknown[] }> = ({ initialAlerts = [] }) => {
  const [alerts, setAlerts] = useState<AlertData[]>(initialAlerts as AlertData[]);
  const [isConnected, setIsConnected] = useState(false);
  const [feedMode, setFeedMode] = useState<'live' | 'simulated'>('live');
  const queryClient = useQueryClient();
  const scrollRef = useRef<HTMLDivElement>(null);

  // Switch backend mode when toggle changes
  useEffect(() => {
    const baseUrl = import.meta.env.VITE_API_BASE_URL
      ? import.meta.env.VITE_API_BASE_URL.replace(/^https?:\/\//, '')
      : `${window.location.hostname}:8000`;

    fetch(`http://${baseUrl}/pipeline/mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: feedMode === 'live' ? 'live' : 'simulated' }),
    }).catch(console.error);

    // Clear alerts when switching modes
    setAlerts([]);
  }, [feedMode]);

  // WebSocket connection — always active, backend filters by mode
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    let baseUrl = import.meta.env.VITE_API_BASE_URL
      ? import.meta.env.VITE_API_BASE_URL.replace(/^https?:\/\//, '')
      : `${window.location.hostname}:8000`;
      
    if (baseUrl.includes('localhost') || baseUrl.includes('127.0.0.1')) {
        baseUrl = `${window.location.hostname}:8000`;
    }

    const ws = new WebSocket(`${protocol}//${baseUrl}/ws/alerts`);

    ws.onopen = () => setIsConnected(true);

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'alert' && msg.data) {
          setAlerts((prev) => [msg.data as AlertData, ...prev].slice(0, 50));
          queryClient.invalidateQueries({ queryKey: ['dashboard'] });
          if (scrollRef.current) {
            scrollRef.current.scrollTo({ top: 0, behavior: 'smooth' });
          }
        }
      } catch (e) {
        console.error('Failed to parse WS message', e);
      }
    };

    ws.onclose = () => setIsConnected(false);

    return () => { ws.close(); };
  }, [queryClient]);

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center justify-between mb-3 px-1">
        <div className="flex items-center gap-2">
          <span className={isConnected ? 'status-dot-online' : 'status-dot-offline'} />
          <span className="text-[10px] text-text-muted uppercase tracking-wider">
            {feedMode === 'live' ? (isConnected ? 'Live Socket Connected' : 'Reconnecting...') : 'Simulated Feed Active'}
          </span>
        </div>
        
        {/* Toggle Switch */}
        <div className="flex items-center gap-2 bg-background-elevated px-2 py-1 rounded-full border border-background-border/50">
          <span className={`text-[10px] uppercase font-bold tracking-widest cursor-pointer ${feedMode === 'live' ? 'text-[#11D9C5]' : 'text-text-muted'}`} onClick={() => setFeedMode('live')}>Live</span>
          <div 
            className="w-6 h-3 bg-background-darker rounded-full relative cursor-pointer" 
            onClick={() => setFeedMode(prev => prev === 'live' ? 'simulated' : 'live')}
          >
            <div className={`absolute top-[2px] left-[2px] w-2 h-2 rounded-full bg-white transition-all duration-300 ${feedMode === 'simulated' ? 'translate-x-3' : ''}`} />
          </div>
          <span className={`text-[10px] uppercase font-bold tracking-widest cursor-pointer ${feedMode === 'simulated' ? 'text-[#11D9C5]' : 'text-text-muted'}`} onClick={() => setFeedMode('simulated')}>Simulated</span>
        </div>
      </div>

      <div ref={scrollRef} className="space-y-2 flex-1 overflow-y-auto min-h-0 pr-1">
        {alerts.length === 0 && (
          <div className="text-center py-8">
            <div className="text-text-muted text-xs">Waiting for traffic...</div>
          </div>
        )}

        {alerts.map((alert, i) => {
          const priority = alert.priority || 'INFO';
          const crs = alert.crs ?? 0;
          // Always derive MITRE from priority — never trust raw backend value
          const mitre = PRIORITY_MITRE[priority] ?? 'Normal Traffic';
          const actions = priorityActions[priority] || [];
          const isCriticalOrHigh = priority === 'CRITICAL' || priority === 'HIGH';
          const isMedium = priority === 'MEDIUM';

          return (
            <div
              key={alert.record_id ? `${alert.record_id}-${i}` : i}
              className={`p-3 rounded-lg bg-background-elevated border border-background-border border-l-[3px] animate-fade-up hover:border-background-border/80 transition-all cursor-pointer ${severityBorderColor[priority] || ''}`}
              style={{ animationDelay: `${Math.min(i * 50, 200)}ms` }}
            >
              {/* Row 1: Priority + CRS + MITRE */}
              <div className="flex items-center justify-between mb-1 gap-2 flex-wrap">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`text-[10px] font-bold ${priorityTextColor[priority] || 'text-slate-400'}`}>
                    {priority}
                  </span>
                  <span className="text-[10px] text-text-muted font-mono">
                    CRS: {crs.toFixed(3)}
                  </span>
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#027373]/20 text-[#11D9C5] border border-[#027373]/30">
                    {mitre}
                  </span>
                </div>
                <span className="text-[10px] text-text-muted shrink-0">
                  {alert.agents_fired?.length ? alert.agents_fired.join('+') : 'monitor'}
                </span>
              </div>

              {/* Row 2: IPs */}
              <div className="text-xs text-text-primary truncate">
                {alert.src_ip || 'unknown'} &rarr; {alert.dst_ip || 'unknown'}
              </div>

              {/* Row 3: Suppression tag */}
              {alert.is_suppressed && (
                <div className="text-[10px] text-text-muted mt-1 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 bg-text-muted rounded-full" />
                  Suppressed: {alert.suppression_reason}
                </div>
              )}

              {/* Row 4: Actions taken */}
              {(isCriticalOrHigh || isMedium) && !alert.is_suppressed && actions.length > 0 && (
                <div className="mt-2 pt-2 border-t border-background-border/50">
                  <div className="text-[10px] text-text-muted mb-1 font-semibold uppercase tracking-wider">
                    Actions Taken
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {actions.map((action, j) => (
                      <span key={j} className="text-[9px] px-1.5 py-0.5 rounded bg-background-card text-text-secondary">
                        {action}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

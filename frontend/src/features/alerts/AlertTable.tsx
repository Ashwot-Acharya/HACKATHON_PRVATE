import React from 'react';
import type { Alert } from '@/types/alert.types';
import { SeverityIndicator } from '@components/common/SeverityIndicator';
import { CRSGauge } from '@components/common/CRSGauge';
import { MITRETag } from '@components/common/MITRETag';

interface Props {
  /** Alerts list. */
  alerts: Alert[];
  /** Row click. */
  onAlertClick?: (id: string) => void;
}

export const AlertTable: React.FC<Props> = ({ alerts, onAlertClick }) => {
  return (
    <div className="flex flex-col h-full overflow-hidden p-4">
      <div className="overflow-x-auto">
        <div className="min-w-[800px]">
          {/* Table Header */}
          <div className="grid grid-cols-6 gap-4 text-xs uppercase tracking-widest font-semibold text-text-muted mb-3 px-2">
            <div>Severity</div>
            <div>Timestamp</div>
            <div>Source IP</div>
            <div>MITRE / Context</div>
            <div>CRS Score</div>
            <div>Status</div>
          </div>
          
          {/* Table Body */}
          <div className="space-y-2 max-h-[calc(100vh-16rem)] overflow-y-auto pr-2 pb-4 scrollbar-thin">
            {alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-text-muted">
                <div className="w-12 h-12 rounded-full border border-background-border border-t-challenge-c3 animate-spin mb-4" />
                <p>Waiting for incoming logs...</p>
              </div>
            ) : (
              alerts.map((a, i) => (
                <button
                  key={a.id}
                  onClick={() => onAlertClick?.(a.id)}
                  className={`w-full text-left grid grid-cols-6 gap-4 items-center p-3 rounded-lg transition-all duration-200 animate-fade-up border border-transparent hover:border-background-border/50 hover:bg-background-elevated group
                    ${a.severity === 'CRITICAL' ? 'bg-red-500/5 hover:bg-red-500/10 hover:border-red-500/30' : 'bg-background-darker/50'}
                  `}
                  style={{ animationDelay: `${Math.min(i * 30, 500)}ms` }}
                >
                  <div className="flex items-center">
                    <SeverityIndicator severity={a.severity} />
                  </div>
                  <span className="text-xs text-text-secondary whitespace-nowrap">
                    {new Date(a.timestamp).toLocaleString()}
                  </span>
                  <span className="text-xs text-text-primary font-mono bg-background-primary/50 px-2 py-1 rounded">
                    {a.sourceIp}
                  </span>
                  <div className="flex items-center group-hover:scale-[1.02] transition-transform">
                    <MITRETag technique={a.mitre} severity={a.severity} />
                  </div>
                  <div>
                    <CRSGauge value={a.crs} />
                  </div>
                  <div>
                    {a.is_suppressed ? (
                      <span className="text-[10px] uppercase font-bold text-text-muted border border-background-border px-2 py-1 rounded">Suppressed</span>
                    ) : (
                      <span className="text-[10px] uppercase font-bold text-challenge-c3 bg-challenge-c3/10 px-2 py-1 rounded">Open</span>
                    )}
                  </div>
                </button>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

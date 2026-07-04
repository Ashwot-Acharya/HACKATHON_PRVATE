import React, { useState } from 'react';
import { AlertTriangle, ShieldAlert, AlertCircle, Info, X, CheckCircle } from 'lucide-react';

export interface ThreatItem {
  id: string;
  sourceIp: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  score: number;
}

interface ThreatTriageListProps {
  title: string;
  data: ThreatItem[];
}

const severityConfig = {
  CRITICAL: { color: 'text-severity-critical', bg: 'bg-severity-critical/10', icon: <ShieldAlert size={16} /> },
  HIGH: { color: 'text-severity-high', bg: 'bg-severity-high/10', icon: <AlertTriangle size={16} /> },
  MEDIUM: { color: 'text-severity-medium', bg: 'bg-severity-medium/10', icon: <AlertCircle size={16} /> },
  LOW: { color: 'text-severity-low', bg: 'bg-severity-low/10', icon: <Info size={16} /> },
};

export const ThreatTriageList: React.FC<ThreatTriageListProps> = ({ title, data }) => {
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [acknowledged, setAcknowledged] = useState<Set<string>>(new Set());

  const handleDismiss = (id: string) => {
    setDismissed(prev => new Set(prev).add(id));
  };

  const handleAcknowledge = (id: string) => {
    setAcknowledged(prev => new Set(prev).add(id));
  };

  const activeData = [...data]
    .filter(t => !dismissed.has(t.id))
    .sort((a, b) => b.score - a.score);

  const dismissedCount = dismissed.size;

  return (
    <div className="bg-bg-panel border border-bg-border rounded-lg shadow-sm flex flex-col h-full relative group">
      {/* Title */}
      <div className="p-3 pb-2 flex items-center justify-between z-10 border-b border-bg-border">
        <span className="text-[12px] font-semibold text-text-secondary tracking-wide uppercase truncate" title={title}>
          {title}
        </span>
        <div className="flex items-center gap-2">
          {dismissedCount > 0 && (
            <span className="text-[10px] text-text-muted">{dismissedCount} dismissed</span>
          )}
          <span className="text-[10px] font-bold text-text-primary bg-bg-elevated px-2 py-0.5 rounded-full">
            {activeData.length}
          </span>
        </div>
      </div>

      <div className="flex-1 w-full overflow-y-auto p-2 space-y-2">
        {activeData.map((threat) => {
          const config = severityConfig[threat.severity] || severityConfig.LOW;
          const isAcked = acknowledged.has(threat.id);
          return (
            <div
              key={threat.id}
              className={`flex items-center justify-between p-2 rounded-md transition-colors border ${
                isAcked
                  ? 'bg-green-50 border-green-200'
                  : 'hover:bg-bg-elevated border-transparent hover:border-bg-border'
              }`}
            >
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-md ${config.bg} ${config.color}`}>
                  {config.icon}
                </div>
                <div>
                  <div className="text-sm font-semibold text-text-primary">{threat.sourceIp}</div>
                  <div className="text-[11px] text-text-secondary">{threat.category}</div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="flex flex-col items-end mr-1">
                  <span className={`text-xs font-bold ${config.color}`}>{threat.severity}</span>
                  <span className="text-[10px] text-text-muted">CRS: {(threat.score * 100).toFixed(1)}</span>
                </div>
                {/* Action buttons */}
                {!isAcked ? (
                  <button
                    onClick={() => handleAcknowledge(threat.id)}
                    title="Acknowledge"
                    className="p-1 rounded hover:bg-green-100 text-text-muted hover:text-green-600 transition-colors"
                  >
                    <CheckCircle size={14} />
                  </button>
                ) : (
                  <span className="text-[10px] text-green-600 font-semibold">ACK</span>
                )}
                <button
                  onClick={() => handleDismiss(threat.id)}
                  title="Dismiss"
                  className="p-1 rounded hover:bg-red-100 text-text-muted hover:text-red-500 transition-colors"
                >
                  <X size={14} />
                </button>
              </div>
            </div>
          );
        })}
        {activeData.length === 0 && (
          <div className="text-center py-4 text-text-muted text-sm">
            {dismissedCount > 0 ? 'All threats have been triaged.' : 'No active threats detected.'}
          </div>
        )}
      </div>
    </div>
  );
};

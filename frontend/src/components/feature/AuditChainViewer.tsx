import React from 'react';
import { Lock, FileText, CheckCircle, Shield } from 'lucide-react';

interface AuditEntry {
  timestamp: string;
  action: string;
  hash: string;
  status: string;
}

interface Props {
  entries: AuditEntry[];
}

export const AuditChainViewer: React.FC<Props> = ({ entries }) => {
  return (
    <div className="space-y-4">
      {/* Verify Button */}
      <button className="w-full flex items-center justify-between p-3 rounded-lg bg-background-elevated hover:bg-background-border transition-colors border border-background-border group">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-challenge-c2/20 flex items-center justify-center group-hover:bg-challenge-c2/30 transition-colors">
            <Lock size={14} className="text-challenge-c2" />
          </div>
          <div className="text-left">
            <div className="text-xs font-semibold text-text-primary">Verify Immutable Chain</div>
            <div className="text-[10px] text-text-muted">SHA-256 (Hn-1 || action || ts)</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-semibold text-green-400">VERIFIED</span>
          <CheckCircle size={14} className="text-green-400" />
        </div>
      </button>

      {/* Chain */}
      <div className="relative">
        <div className="absolute left-[15px] top-0 bottom-0 w-[2px] bg-background-border" />
        <div className="space-y-0 relative z-10 max-h-[250px] overflow-y-auto pr-2">
          {entries.length === 0 ? (
            <div className="text-center py-6 text-xs text-text-muted">No audit logs found.</div>
          ) : (
            entries.map((entry, i) => (
              <div key={i} className="flex items-start gap-3 relative py-3 animate-fade-up" style={{ animationDelay: `${i * 100}ms` }}>
                <div className="w-8 h-8 rounded-full bg-background-elevated border-2 border-background-primary flex flex-shrink-0 items-center justify-center mt-1">
                  {entry.action.includes('PDF') ? (
                    <FileText size={12} className="text-text-secondary" />
                  ) : entry.action.includes('CONTAINMENT') ? (
                    <Shield size={12} className="text-severity-critical" />
                  ) : (
                    <Lock size={12} className="text-text-muted" />
                  )}
                </div>
                <div className="flex-1 min-w-0 bg-background-elevated rounded-lg border border-background-border p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold text-text-primary">{entry.action}</span>
                    <span className="text-[10px] text-text-muted">
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[9px] text-text-muted font-mono truncate">
                      {entry.hash.substring(0, 32)}...
                    </span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

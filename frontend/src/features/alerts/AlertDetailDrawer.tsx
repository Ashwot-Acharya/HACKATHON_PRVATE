import React, { useEffect, useState } from 'react';
import type { Alert } from '@/types/alert.types';
import { SeverityIndicator } from '@components/common/SeverityIndicator';
import { CRSGauge } from '@components/common/CRSGauge';
import { MITRETag } from '@components/common/MITRETag';
import { useAlertStore } from '@stores/alertStore';
import { X, Network, Server, Shield, Clock, Crosshair, Cpu, FileJson, CheckCircle } from 'lucide-react';

interface Props {
  alert: Alert | null;
  onClose: () => void;
}

export const AlertDetailDrawer: React.FC<Props> = ({ alert, onClose }) => {
  const [isOpen, setIsOpen] = useState(false);
  const updateAlert = useAlertStore(s => s.updateAlert);

  const handleSuppress = () => {
    if (alert) {
      updateAlert(alert.id, { is_suppressed: true });
      // Show simple alert for demo purposes
      window.alert(`Alert ${alert.id} suppressed as False Positive.`);
    }
  };

  const handleInvestigate = () => {
    window.alert(`Navigating to workspace investigation for ${alert?.id}...\n(Feature coming soon!)`);
  };

  useEffect(() => {
    if (alert) setIsOpen(true);
    else setIsOpen(false);
  }, [alert]);

  if (!alert) return null;

  return (
    <>
      {/* Backdrop */}
      <div 
        className={`fixed inset-0 z-40 bg-black/60 backdrop-blur-sm transition-opacity duration-300 ${isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'}`}
        onClick={onClose}
      />
      
      {/* Drawer */}
      <div 
        className={`fixed inset-y-0 right-0 z-50 w-full md:w-[600px] bg-background-elevated border-l border-background-border shadow-2xl overflow-y-auto transition-transform duration-300 ease-in-out ${isOpen ? 'translate-x-0' : 'translate-x-full'}`}
      >
        <div className="p-6">
          {/* Header */}
          <div className="flex items-start justify-between mb-8">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Shield size={16} className="text-challenge-c1" />
                <span className="text-xs uppercase tracking-widest text-text-secondary font-bold">Log Details</span>
              </div>
              <h2 className="text-xl font-bold text-text-primary font-mono break-all">{alert.id}</h2>
            </div>
            <button 
              onClick={onClose} 
              className="p-2 hover:bg-background-darker rounded-lg transition-colors text-text-muted hover:text-text-primary"
            >
              <X size={20} />
            </button>
          </div>

          {/* Severity & CRS Banner */}
          <div className="flex items-center gap-6 p-4 rounded-xl bg-background-darker/50 border border-background-border mb-8">
            <div className="flex-1">
              <div className="text-[10px] text-text-muted uppercase tracking-widest mb-1">Severity</div>
              <SeverityIndicator severity={alert.severity} />
            </div>
            <div className="w-px h-10 bg-background-border" />
            <div className="flex-1">
              <div className="text-[10px] text-text-muted uppercase tracking-widest mb-1">Composite Risk Score</div>
              <CRSGauge value={alert.crs} />
            </div>
          </div>

          {/* Grid Information */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-text-muted mb-2">
                <Clock size={14} />
                <span className="text-xs uppercase tracking-wider font-semibold">Timestamp</span>
              </div>
              <div className="text-sm text-text-primary bg-background-darker p-3 rounded-lg border border-background-border/50">
                {new Date(alert.timestamp).toLocaleString()}
              </div>
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2 text-text-muted mb-2">
                <Crosshair size={14} />
                <span className="text-xs uppercase tracking-wider font-semibold">Classification</span>
              </div>
              <div className="p-2 bg-background-darker rounded-lg border border-background-border/50 flex justify-center">
                <MITRETag technique={alert.mitre} severity={alert.severity} />
              </div>
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2 text-text-muted mb-2">
                <Server size={14} />
                <span className="text-xs uppercase tracking-wider font-semibold">Source IP</span>
              </div>
              <div className="text-sm text-text-primary font-mono bg-background-darker p-3 rounded-lg border border-background-border/50">
                {alert.sourceIp}
              </div>
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2 text-text-muted mb-2">
                <Network size={14} />
                <span className="text-xs uppercase tracking-wider font-semibold">Target IP</span>
              </div>
              <div className="text-sm text-text-primary font-mono bg-background-darker p-3 rounded-lg border border-background-border/50">
                {alert.destinationIp || 'Unknown'}
              </div>
            </div>
          </div>

          {/* Agents */}
          <div className="space-y-3 mb-8">
            <div className="flex items-center gap-2 text-text-muted">
              <Cpu size={14} />
              <span className="text-xs uppercase tracking-wider font-semibold">Detection Engines Fired</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {alert.agents.length === 0 ? (
                <span className="text-sm text-text-secondary">None</span>
              ) : (
                alert.agents.map((agent, i) => (
                  <span key={i} className="px-3 py-1 bg-challenge-c2/10 text-challenge-c2 border border-challenge-c2/30 rounded-full text-xs font-semibold">
                    {agent.replace('_agent', '').toUpperCase()} ENGINE
                  </span>
                ))
              )}
            </div>
          </div>

          {/* Raw Payload Section */}
          <div className="space-y-3 mb-8">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-text-muted">
                <FileJson size={14} />
                <span className="text-xs uppercase tracking-wider font-semibold">Raw Contaminated Log Data</span>
              </div>
            </div>
            <div className="bg-background-darker border border-background-border rounded-lg p-3 overflow-x-auto">
              <pre className="text-[10px] text-text-primary font-mono whitespace-pre-wrap">
                {alert.raw_payload 
                  ? JSON.stringify(alert.raw_payload, null, 2)
                  : JSON.stringify(alert, null, 2)}
              </pre>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-col md:flex-row gap-3 pt-6 border-t border-background-border pb-8">
            <button 
              onClick={handleInvestigate}
              className="flex-1 py-3 bg-red-500/10 hover:bg-red-500/20 text-red-400 font-semibold rounded-lg border border-red-500/30 transition-all flex items-center justify-center gap-2"
            >
              <Crosshair size={16} />
              Investigate in Workspace
            </button>
            <button 
              onClick={handleSuppress}
              disabled={alert.is_suppressed}
              className={`flex-1 py-3 font-semibold rounded-lg border transition-all flex items-center justify-center gap-2
                ${alert.is_suppressed 
                  ? 'bg-[#11D9C5]/10 text-[#11D9C5] border-[#11D9C5]/30 opacity-50 cursor-not-allowed' 
                  : 'bg-background-darker hover:bg-background-border text-text-primary border-background-border'}`}
            >
              <CheckCircle size={16} />
              {alert.is_suppressed ? 'Suppressed' : 'Mark as False Positive'}
            </button>
          </div>
        </div>
      </div>
    </>
  );
};

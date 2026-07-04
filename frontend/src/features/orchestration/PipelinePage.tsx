import React, { useEffect, useState } from 'react';
import { useAlertStore } from '@stores/alertStore';
import type { Alert } from '@/types/alert.types';

const AgentNode: React.FC<{
  title: string;
  state: 'idle' | 'processing' | 'passive';
  statusText?: string;
}> = ({ title, state, statusText }) => {
  let glassClass = "border-slate-200 bg-white/60 backdrop-blur-md text-slate-500 shadow-sm"; 
  let textClass = "text-slate-500";
  let pulseGlow = "";

  if (state === 'processing') {
    glassClass = "border-emerald-400/50 bg-emerald-50/80 backdrop-blur-xl shadow-[0_0_20px_rgba(52,211,153,0.3)]";
    textClass = "text-emerald-600 font-bold tracking-widest animate-pulse";
    pulseGlow = "absolute -inset-1 bg-gradient-to-r from-emerald-300 to-green-200 rounded-xl blur opacity-30 animate-pulse -z-10";
  } else if (state === 'passive') {
    glassClass = "border-blue-300/50 bg-blue-50/80 backdrop-blur-md shadow-[0_0_15px_rgba(96,165,250,0.2)]";
    textClass = "text-blue-600 font-medium tracking-wider";
  }

  const containerClass = `
    relative z-20 flex flex-col items-center justify-center p-5 rounded-xl border transition-all duration-1000 ease-in-out transform
    ${state === 'processing' ? 'scale-105' : 'scale-100'}
    ${glassClass}
  `;

  return (
    <div className="relative" style={{ width: '200px', height: '140px' }}>
      {pulseGlow && <div className={pulseGlow}></div>}
      <div className={containerClass} style={{ width: '100%', height: '100%' }}>
        <div className={`text-sm font-extrabold text-center mb-3 ${state === 'processing' ? 'text-slate-800 drop-shadow-sm' : 'text-slate-600'}`}>
          {title}
        </div>
        {statusText && (
          <div className={`text-[10px] uppercase font-mono px-3 py-1.5 rounded-full bg-white/80 border border-slate-200 shadow-sm ${textClass}`}>
            {statusText}
          </div>
        )}
      </div>
    </div>
  );
};

const Connector: React.FC<{ active: boolean }> = ({ active }) => (
  <div className="flex-1 h-[2px] bg-slate-200 mx-2 relative overflow-hidden rounded-full min-w-[60px] max-w-[100px]">
    {active && (
      <div className="absolute inset-0 w-[200%] bg-gradient-to-r from-transparent via-emerald-400 to-transparent animate-pulse -ml-[100%]"></div>
    )}
  </div>
);

const PipelinePage: React.FC = () => {
  const alerts = useAlertStore((state) => state.alerts);
  const [latestAlert, setLatestAlert] = useState<Alert | null>(null);
  
  // Track aggregated state over the last 1.5 seconds to prevent flickering
  const [activeAgents, setActiveAgents] = useState<Set<string>>(new Set());
  const [isProcessing, setIsProcessing] = useState(false);
  const [hasCritical, setHasCritical] = useState(false);
  const [isSuppressed, setIsSuppressed] = useState(false);

  useEffect(() => {
    if (alerts.length > 0) {
      const current = alerts[0];
      setLatestAlert(current);
      setIsProcessing(true);
      
      setActiveAgents(prev => {
        const next = new Set(prev);
        if (current.agents) {
          current.agents.forEach(a => next.add(a.toLowerCase()));
        }
        return next;
      });
      
      if (current.severity === 'CRITICAL') setHasCritical(true);
      if (current.is_suppressed) setIsSuppressed(true);

      const timeout = setTimeout(() => {
        setIsProcessing(false);
        setActiveAgents(new Set());
        setHasCritical(false);
        setIsSuppressed(false);
      }, 1500); // Hold the processing state for 1.5 seconds

      return () => clearTimeout(timeout);
    }
  }, [alerts]);

  return (
    <div className="flex flex-col h-full bg-slate-50 text-slate-800 overflow-y-auto p-8 space-y-8 font-sans relative">
      
      {/* Premium Background Effects */}
      <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] rounded-full bg-indigo-100/40 blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-[-20%] right-[-10%] w-[50%] h-[50%] rounded-full bg-emerald-100/40 blur-[120px] pointer-events-none"></div>
      
      {/* Header */}
      <div className="flex items-center justify-between relative z-10">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight text-slate-900 flex items-center gap-3 drop-shadow-sm">
            Pipeline Orchestration
          </h1>
          <p className="text-slate-500 mt-2 text-sm font-medium">Live visualization of the BBN fusion engine and ML processing pipeline.</p>
        </div>
        <div className="px-5 py-2.5 bg-white/80 backdrop-blur-md rounded-full border border-slate-200 flex items-center gap-3 shadow-sm">
          <span className="relative flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]"></span>
          </span>
          <span className="font-mono text-xs font-bold tracking-widest text-emerald-600">PIPELINE ONLINE</span>
        </div>
      </div>

      {/* Orchestrator Canvas */}
      <div className="flex-1 bg-white/60 backdrop-blur-sm border border-slate-200 rounded-2xl p-10 relative flex flex-col justify-center overflow-x-auto min-h-[600px] shadow-lg">
        
        {/* Nodes Container */}
        <div className="relative z-10 flex items-center justify-center min-w-[1000px] gap-2 px-10">
          
          {/* Stage 1: Ingestion */}
          <div className="flex flex-col gap-4">
            <AgentNode 
              title="Suricata EVE Ingest" 
              state={isProcessing ? 'processing' : 'idle'} 
              statusText={isProcessing ? "STREAMING" : "WAITING"}
            />
          </div>

          <Connector active={isProcessing} />

          {/* Stage 2: ML Agents (Parallel) */}
          <div className="flex flex-col gap-10">
            <AgentNode 
              title="Packet Agent (Layer 3)" 
              state={isProcessing ? (activeAgents.has('packet') ? 'processing' : 'passive') : 'idle'}
              statusText={isProcessing ? (activeAgents.has('packet') ? 'FIRED' : 'ANALYZED') : 'IDLE'}
            />
            <AgentNode 
              title="Flow Agent (Layer 2)" 
              state={isProcessing ? (activeAgents.has('flow') ? 'processing' : 'passive') : 'idle'}
              statusText={isProcessing ? (activeAgents.has('flow') ? 'FIRED' : 'ANALYZED') : 'IDLE'}
            />
            <AgentNode 
              title="Behavior Agent (Layer 1)" 
              state={isProcessing ? (activeAgents.has('behavior') ? 'processing' : 'passive') : 'idle'}
              statusText={isProcessing ? (activeAgents.has('behavior') ? 'FIRED' : 'ANALYZED') : 'IDLE'}
            />
          </div>

          <Connector active={isProcessing} />

          {/* Stage 3: Correlation */}
          <div className="flex flex-col gap-4">
            <AgentNode 
              title="BBN Fusion Engine" 
              state={isProcessing ? (isSuppressed ? 'passive' : 'processing') : 'idle'}
              statusText={isProcessing ? (isSuppressed ? 'SUPPRESSED' : (hasCritical ? 'CRITICAL MATCH' : 'CORRELATED')) : 'IDLE'}
            />
          </div>

          <Connector active={isProcessing} />

          {/* Stage 4: Response */}
          <div className="flex flex-col gap-4">
            <AgentNode 
              title="Response Agent" 
              state={isProcessing ? (hasCritical && !isSuppressed ? 'processing' : 'passive') : 'idle'}
              statusText={isProcessing ? (hasCritical && !isSuppressed ? 'CONTAINMENT' : 'STANDBY') : 'IDLE'}
            />
          </div>

        </div>
      </div>

      {/* Latest Event Context */}
      <div className="bg-white/80 backdrop-blur-md p-6 rounded-2xl border border-slate-200 shadow-md relative z-10">
        <h3 className="text-sm font-extrabold uppercase tracking-widest text-slate-500 mb-6 flex items-center gap-2">
          Latest Flow Context
        </h3>
        {latestAlert ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            <div className="bg-slate-50 p-4 rounded-xl border border-slate-100">
              <div className="text-[10px] text-slate-400 uppercase tracking-widest mb-1.5 font-semibold">Source IP</div>
              <div className="font-mono text-sm text-slate-800">{latestAlert.sourceIp}</div>
            </div>
            <div className="bg-slate-50 p-4 rounded-xl border border-slate-100">
              <div className="text-[10px] text-slate-400 uppercase tracking-widest mb-1.5 font-semibold">Destination IP</div>
              <div className="font-mono text-sm text-slate-800">{latestAlert.destinationIp || 'Unknown'}</div>
            </div>
            <div className="bg-slate-50 p-4 rounded-xl border border-slate-100">
              <div className="text-[10px] text-slate-400 uppercase tracking-widest mb-1.5 font-semibold">BBN Confidence</div>
              <div className="font-mono text-lg font-bold text-emerald-600 drop-shadow-[0_0_2px_rgba(16,185,129,0.2)]">
                {Math.round(latestAlert.crs * 100)}%
              </div>
            </div>
            <div className="bg-slate-50 p-4 rounded-xl border border-slate-100">
              <div className="text-[10px] text-slate-400 uppercase tracking-widest mb-1.5 font-semibold">Suppression</div>
              <div className={`font-mono text-sm font-medium ${latestAlert.is_suppressed ? 'text-amber-600' : 'text-emerald-600'}`}>
                {latestAlert.is_suppressed ? latestAlert.suppression_reason : 'None'}
              </div>
            </div>
          </div>
        ) : (
          <div className="text-slate-500 text-sm italic font-medium py-4 text-center bg-slate-50 rounded-xl border border-slate-100">
            Awaiting network telemetry...
          </div>
        )}
      </div>

    </div>
  );
};

export default PipelinePage;

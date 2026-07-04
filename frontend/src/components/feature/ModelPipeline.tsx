import React, { useEffect, useState, useRef } from 'react';
import { Shield, Activity, Brain, Network, Zap } from 'lucide-react';
import { useQueryClient } from '@tanstack/react-query';

const PIPELINE_NODES = [
  { id: 'packet', label: 'Packet Agent', icon: Shield },
  { id: 'flow', label: 'Flow Agent', icon: Activity },
  { id: 'behavior', label: 'Behavior Agent', icon: Brain },
  { id: 'correlation', label: 'Correlation Agent', icon: Network },
  { id: 'response', label: 'Response Agent', icon: Zap }
];

export const ModelPipeline: React.FC = () => {
  const [animations, setAnimations] = useState<Record<string, { key: number, priority: string }>>({});
  const queryClient = useQueryClient();

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    let baseUrl = import.meta.env.VITE_API_BASE_URL
      ? import.meta.env.VITE_API_BASE_URL.replace(/^https?:\/\//, '')
      : `${window.location.hostname}:8000`;
      
    if (baseUrl.includes('localhost') || baseUrl.includes('127.0.0.1')) {
        baseUrl = `${window.location.hostname}:8000`;
    }

    const ws = new WebSocket(`${protocol}//${baseUrl}/ws/alerts`);

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'alert' && msg.data) {
          const alert = msg.data;
          const priority = alert.priority || 'INFO';
          const isNormal = priority === 'INFO';
          const fired = alert.agents_fired || [];

          let agentsToAnimate: string[] = [];

          if (isNormal) {
            // Pulse all agents sequentially for normal traffic
            agentsToAnimate = PIPELINE_NODES.map(n => n.id);
          } else {
            // Pulse only the specific agents that fired
            agentsToAnimate = PIPELINE_NODES.map(n => n.id).filter(id => {
              if (id === 'correlation') return true; // Always correlates alerts
              if (id === 'response' && ['HIGH', 'CRITICAL'].includes(priority)) return true;
              return fired.some((f: string) => f.toLowerCase().includes(id));
            });
          }

          setAnimations(prev => {
            const next = { ...prev };
            agentsToAnimate.forEach((id, idx) => {
              // Add slight delay based on pipeline position to simulate flow
              setTimeout(() => {
                setAnimations(curr => ({
                  ...curr,
                  [id]: { key: Date.now() + Math.random(), priority }
                }));
              }, idx * 100);
            });
            return next;
          });
        }
      } catch (e) {
        console.error('Failed to parse WS message in pipeline', e);
      }
    };

    return () => { ws.close(); };
  }, []);

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'CRITICAL': return 'rgba(239, 68, 68, 1)'; // red-500
      case 'HIGH': return 'rgba(249, 115, 22, 1)'; // orange-500
      case 'MEDIUM': return 'rgba(234, 179, 8, 1)'; // yellow-500
      case 'LOW': return 'rgba(59, 130, 246, 1)'; // blue-500
      case 'INFO': 
      default: return 'rgba(56, 189, 248, 1)'; // light-blue-400
    }
  };

  // Zoom and Pan State
  const [scale, setScale] = useState(1);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const isDragging = useRef(false);
  const dragStart = useRef({ x: 0, y: 0 });
  const containerRef = useRef<HTMLDivElement>(null);

  // We add a non-passive wheel listener directly to the container to prevent scrolling while zooming
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const handleWheel = (e: WheelEvent) => {
      e.preventDefault();
      const zoomSensitivity = 0.002;
      const delta = -e.deltaY * zoomSensitivity;
      setScale(prev => Math.min(Math.max(0.3, prev + delta), 3));
    };
    el.addEventListener('wheel', handleWheel, { passive: false });
    return () => el.removeEventListener('wheel', handleWheel);
  }, []);

  const handleMouseDown = (e: React.MouseEvent) => {
    isDragging.current = true;
    dragStart.current = { x: e.clientX - position.x, y: e.clientY - position.y };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging.current) return;
    setPosition({
      x: e.clientX - dragStart.current.x,
      y: e.clientY - dragStart.current.y
    });
  };

  const handleMouseUpOrLeave = () => {
    isDragging.current = false;
  };

  // Reset View
  const resetView = () => {
    setScale(1);
    setPosition({ x: 0, y: 0 });
  };

  return (
    <div 
      ref={containerRef}
      className="relative w-full h-[320px] lg:h-[380px] rounded-lg overflow-hidden border border-background-border group bg-background-elevated/20 flex flex-col justify-center cursor-grab active:cursor-grabbing"
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUpOrLeave}
      onMouseLeave={handleMouseUpOrLeave}
    >
      
      {/* Inline styles for dynamic keyframes */}
      <style>{`
        @keyframes pipeline-glow-CRITICAL {
          0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); border-color: rgba(239, 68, 68, 1); background: rgba(239, 68, 68, 0.2); transform: scale(1.05); }
          50% { box-shadow: 0 0 30px 10px rgba(239, 68, 68, 0.4); border-color: rgba(239, 68, 68, 0.8); background: rgba(239, 68, 68, 0.1); transform: scale(1.02); }
          100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); border-color: rgba(31, 35, 55, 0.6); background: rgba(17, 20, 34, 0.75); transform: scale(1); }
        }
        @keyframes pipeline-glow-HIGH {
          0% { box-shadow: 0 0 0 0 rgba(249, 115, 22, 0.7); border-color: rgba(249, 115, 22, 1); background: rgba(249, 115, 22, 0.2); transform: scale(1.05); }
          50% { box-shadow: 0 0 30px 10px rgba(249, 115, 22, 0.4); border-color: rgba(249, 115, 22, 0.8); background: rgba(249, 115, 22, 0.1); transform: scale(1.02); }
          100% { box-shadow: 0 0 0 0 rgba(249, 115, 22, 0); border-color: rgba(31, 35, 55, 0.6); background: rgba(17, 20, 34, 0.75); transform: scale(1); }
        }
        @keyframes pipeline-glow-MEDIUM {
          0% { box-shadow: 0 0 0 0 rgba(234, 179, 8, 0.7); border-color: rgba(234, 179, 8, 1); background: rgba(234, 179, 8, 0.2); transform: scale(1.05); }
          50% { box-shadow: 0 0 30px 10px rgba(234, 179, 8, 0.4); border-color: rgba(234, 179, 8, 0.8); background: rgba(234, 179, 8, 0.1); transform: scale(1.02); }
          100% { box-shadow: 0 0 0 0 rgba(234, 179, 8, 0); border-color: rgba(31, 35, 55, 0.6); background: rgba(17, 20, 34, 0.75); transform: scale(1); }
        }
        @keyframes pipeline-glow-LOW {
          0% { box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.7); border-color: rgba(59, 130, 246, 1); background: rgba(59, 130, 246, 0.2); transform: scale(1.05); }
          50% { box-shadow: 0 0 30px 10px rgba(59, 130, 246, 0.4); border-color: rgba(59, 130, 246, 0.8); background: rgba(59, 130, 246, 0.1); transform: scale(1.02); }
          100% { box-shadow: 0 0 0 0 rgba(59, 130, 246, 0); border-color: rgba(31, 35, 55, 0.6); background: rgba(17, 20, 34, 0.75); transform: scale(1); }
        }
        @keyframes pipeline-glow-INFO {
          0% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.5); border-color: rgba(56, 189, 248, 0.8); background: rgba(56, 189, 248, 0.1); }
          50% { box-shadow: 0 0 15px 5px rgba(56, 189, 248, 0.2); border-color: rgba(56, 189, 248, 0.5); background: rgba(56, 189, 248, 0.05); }
          100% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0); border-color: rgba(31, 35, 55, 0.6); background: rgba(17, 20, 34, 0.75); }
        }
        
        /* Line flow animation */
        @keyframes line-flow {
          0% { background-position: -200% 0; }
          100% { background-position: 200% 0; }
        }
      `}</style>

      {/* The Pan/Zoom Layer */}
      <div 
        className="w-full flex items-center justify-center pointer-events-none"
        style={{
          transform: `translate(${position.x}px, ${position.y}px) scale(${scale})`,
          transition: isDragging.current ? 'none' : 'transform 0.1s ease-out'
        }}
      >
        <div className="flex items-center justify-between w-[900px] min-w-[900px] relative px-8 pointer-events-auto">
          {/* Background connecting lines */}
          <div className="absolute top-1/2 left-[5%] right-[5%] h-1 bg-background-border/50 -translate-y-1/2 rounded-full overflow-hidden">
             <div 
               className="w-full h-full opacity-30"
               style={{
                 background: 'linear-gradient(90deg, transparent 0%, rgba(56, 189, 248, 0.8) 50%, transparent 100%)',
                 backgroundSize: '200% 100%',
                 animation: 'line-flow 2s linear infinite'
               }}
             />
          </div>

          {PIPELINE_NODES.map((node, index) => {
            const anim = animations[node.id];
            const Icon = node.icon;
            
            return (
              <div key={node.id} className="relative flex flex-col items-center z-10 w-32">
                <div 
                  key={anim?.key || 'static'} 
                  className="w-16 h-16 lg:w-20 lg:h-20 rounded-xl glass-panel flex items-center justify-center transition-all duration-300 relative group bg-[#111422] shadow-xl"
                  style={{
                    animation: anim ? `pipeline-glow-${anim.priority} 1s ease-out forwards` : 'none',
                  }}
                >
                  <Icon size={32} className="text-text-primary/80 group-hover:text-text-primary transition-colors" />
                  
                  {/* Node status badge if needed */}
                  {anim && anim.priority !== 'INFO' && (
                    <div 
                      className="absolute -top-2 -right-2 w-4 h-4 rounded-full border-2 border-background-primary shadow-lg"
                      style={{ backgroundColor: getPriorityColor(anim.priority) }}
                    />
                  )}
                </div>
                
                <div className="mt-4 text-center">
                  <span className="text-[11px] lg:text-xs font-semibold text-text-primary/90 whitespace-nowrap block mb-1">
                    {node.label}
                  </span>
                  <span className="text-[9px] lg:text-[10px] text-text-muted uppercase tracking-wider block">
                    {index === 3 ? 'Fusion' : index === 4 ? 'Action' : 'Inference'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* UI Controls & Legend */}
      <div className="absolute top-3 right-3 flex gap-2 z-20">
        <button 
          onClick={resetView}
          className="bg-background-elevated/80 hover:bg-background-elevated text-xs px-2 py-1 rounded border border-background-border text-text-muted hover:text-text-primary transition-colors"
        >
          Reset View
        </button>
      </div>

      <div className="absolute top-3 left-3 bg-background-elevated/80 backdrop-blur-sm border border-background-border rounded p-2 flex flex-col gap-1.5 opacity-50 group-hover:opacity-100 transition-opacity z-20">
        <div className="flex items-center gap-1.5 text-[9px] text-text-primary font-medium">
          <div className="w-2 h-2 rounded-full bg-sky-400" /> Normal Traffic
        </div>
        <div className="flex items-center gap-1.5 text-[9px] text-text-primary font-medium">
          <div className="w-2 h-2 rounded-full bg-yellow-500" /> Suspicious / Alert
        </div>
        <div className="flex items-center gap-1.5 text-[9px] text-text-primary font-medium">
          <div className="w-2 h-2 rounded-full bg-red-500" /> Critical Threat
        </div>
      </div>
    </div>
  );
};

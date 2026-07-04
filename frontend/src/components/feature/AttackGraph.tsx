import React, { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import { useQuery } from '@tanstack/react-query';
import { dashboardService } from '@services/dashboard.service';

const NODE_COLORS: Record<string, string> = {
  safe: '#11D9C5', // bright cyan/teal highlight
  suspicious: '#f59e0b', // c2/amber
  compromised: '#ef4444', // red
  isolated: '#4A7A8F', // muted gray-blue
};

const EDGE_COLORS = {
  normal: 'rgba(10,48,96,0.5)',
  attack: 'rgba(245,158,11,0.5)',
  c2: 'rgba(239,68,68,0.5)',
};

export const AttackGraph: React.FC = () => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<any>(null);
  
  const { data } = useQuery({
    queryKey: ['dashboard', 'graph'],
    queryFn: dashboardService.getGraph,
    refetchInterval: 5000,
  });

  useEffect(() => {
    if (!containerRef.current || !data) return;

    if (!cyRef.current) {
      cyRef.current = cytoscape({
        container: containerRef.current,
        style: [
          {
            selector: 'node',
            style: {
              'background-color': (ele: any) => NODE_COLORS[ele.data('state') as string] || NODE_COLORS.safe,
              'label': 'data(label)',
              'color': '#fff',
              'font-size': '12px',
              'font-family': 'Inter',
              'font-weight': '600',
              'text-valign': 'bottom',
              'text-margin-y': 10,
              'width': 44,
              'height': 44,
              'border-width': 3,
              'border-color': 'rgba(255,255,255,0.2)',
              'shadow-blur': 15,
              'shadow-color': (ele: any) => NODE_COLORS[ele.data('state') as string] || NODE_COLORS.safe,
              'shadow-opacity': (ele: any) => (ele.data('state') === 'safe' ? 0.3 : 0.8),
              'shadow-offset-x': 0,
              'shadow-offset-y': 0,
              'transition-property': 'background-color, shadow-color, shadow-opacity',
              'transition-duration': 300,
            }
          },
          {
            selector: 'edge',
            style: {
              'width': 2.5,
              'line-style': 'dashed',
              'line-dash-pattern': [6, 4],
              'line-color': (ele: any) => {
                const type = ele.data('type');
                if (type === 'c2-channel') return EDGE_COLORS.c2;
                if (type === 'attack') return EDGE_COLORS.attack;
                return EDGE_COLORS.normal;
              },
              'target-arrow-shape': 'triangle',
              'target-arrow-color': (ele: any) => {
                const type = ele.data('type');
                if (type === 'c2-channel') return EDGE_COLORS.c2;
                if (type === 'attack') return EDGE_COLORS.attack;
                return EDGE_COLORS.normal;
              },
              'curve-style': 'bezier',
              'label': 'data(label)',
              'font-size': '10px',
              'font-family': 'Inter',
              'color': 'rgba(255,255,255,0.9)',
              'text-background-color': '#011126',
              'text-background-opacity': 0.85,
              'text-background-padding': '6px',
              'text-background-shape': 'roundrectangle',
              'text-rotation': 'autorotate',
              'text-margin-y': -10
            }
          }
        ],
        layout: {
          name: 'breadthfirst',
          directed: true,
          padding: 40,
          spacingFactor: 1.2,
          animate: true,
          animationDuration: 500,
        }
      });
    }

    const cy = cyRef.current;
    cy.elements().remove();
    cy.add(
      data.nodes.map(n => ({ data: { id: n.id, label: n.label, state: n.state, type: n.type } }))
    );
    cy.add(
      data.edges.map(e => ({ data: { id: e.id, source: e.source, target: e.target, label: e.label, type: e.type } }))
    );

    cy.layout({ 
      name: 'breadthfirst', 
      directed: true, 
      padding: 60,
      spacingFactor: 1.8,
      animate: true,
      animationDuration: 700
    }).run();

    // Animate flow of data/threats along the edges
    let offset = 0;
    let animationId: number;
    const animateEdges = () => {
      offset -= 0.5; // Controls speed and direction
      if (cyRef.current) {
        // Fast flow for attacks, slow flow for normal traffic
        cyRef.current.edges().forEach((edge: any) => {
          const type = edge.data('type');
          const speedMultiplier = (type === 'attack' || type === 'c2-channel') ? 3 : 1;
          edge.style('line-dash-offset', offset * speedMultiplier);
        });
      }
      animationId = requestAnimationFrame(animateEdges);
    };
    animateEdges();

    return () => {
      if (animationId) cancelAnimationFrame(animationId);
      // Don't destroy on unmount to keep cache if possible, but actually we do to prevent memory leaks
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [data]);

  return (
    <div className="relative w-full h-[450px] lg:h-[550px] rounded-lg overflow-hidden cy-container border border-background-border group bg-background-elevated/20">
      <div ref={containerRef} className="absolute inset-0" />
      {/* Legend */}
      <div className="absolute top-3 left-3 bg-background-elevated/80 backdrop-blur-sm border border-background-border rounded p-2 flex flex-col gap-1.5 opacity-50 group-hover:opacity-100 transition-opacity">
        <div className="flex items-center gap-1.5 text-[9px] text-text-primary font-medium">
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: NODE_COLORS.safe }} /> Normal Node
        </div>
        <div className="flex items-center gap-1.5 text-[9px] text-text-primary font-medium">
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: NODE_COLORS.suspicious }} /> Suspicious / Alert
        </div>
        <div className="flex items-center gap-1.5 text-[9px] text-text-primary font-medium">
          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: NODE_COLORS.compromised }} /> Compromised
        </div>
      </div>
    </div>
  );
};

import cytoscape, { Core, ElementDefinition } from 'cytoscape';
import { useRef, useEffect } from 'react';

export type NodeState = 'safe' | 'suspicious' | 'compromised' | 'isolated';

export const useCytoscapeGraph = () => {
  const cyRef = useRef<Core | null>(null);

  const initGraph = (container: HTMLDivElement, nodes: ElementDefinition[], edges: ElementDefinition[]) => {
    if (cyRef.current) destroyGraph();
    cyRef.current = cytoscape({ container, elements: { nodes, edges }, style: [], layout: { name: 'grid' } });
  };

  const updateNodeState = (nodeId: string, state: NodeState) => {
    const cy = cyRef.current;
    if (!cy) return;
    const node = cy.getElementById(nodeId);
    if (node) node.data('state', state);
  };

  const animateAPTProgression = (steps: string[], intervalMs: number) => {
    const cy = cyRef.current;
    if (!cy) return () => {};
    let i = 0;
    const t = setInterval(() => {
      if (i >= steps.length) { clearInterval(t); return; }
      const id = steps[i];
      const n = cy.getElementById(id);
      if (n) n.data('state', 'compromised');
      i += 1;
    }, intervalMs);
    return () => clearInterval(t);
  };

  const resetGraph = () => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().forEach((n: any) => n.data('state', 'safe'));
  };

  const highlightBlastRadius = (nodeId: string) => {
    const cy = cyRef.current;
    if (!cy) return;
    const center = cy.getElementById(nodeId);
    if (!center) return;
    const neighbors = center.closedNeighborhood().nodes();
    cy.elements().removeClass('highlight');
    neighbors.addClass('highlight');
  };

  const destroyGraph = () => {
    if (cyRef.current) {
      cyRef.current.destroy();
      cyRef.current = null;
    }
  };

  useEffect(() => {
    return () => destroyGraph();
  }, []);

  return { initGraph, updateNodeState, animateAPTProgression, resetGraph, highlightBlastRadius, destroyGraph } as const;
};

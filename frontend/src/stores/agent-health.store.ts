import create from 'zustand';
import { AgentStatus } from '@/types/agent.types';

interface AgentHealthState {
  agents: Record<string, AgentStatus>;
  lastUpdated: string | null;
  setAllAgents: (list: AgentStatus[]) => void;
  updateAgentStatus: (agent: AgentStatus) => void;
}

export const useAgentHealthStore = create<AgentHealthState>((set) => ({
  agents: {},
  lastUpdated: null,
  setAllAgents: (list) => set({ agents: Object.fromEntries(list.map((a) => [a.id, a])), lastUpdated: new Date().toISOString() }),
  updateAgentStatus: (agent) => set((s) => ({ agents: { ...s.agents, [agent.id]: agent }, lastUpdated: new Date().toISOString() }))
}));

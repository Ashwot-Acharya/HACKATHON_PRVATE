import { apiClient } from '@lib/axios';
import { AgentStatusSchema } from '@/types/agent.types';

export const agentsService = {
  getHealth: async () => {
    const res = await apiClient.get('/health');
    const loaded = res.data.agents_loaded;
    
    // Map dictionary { 'packet_agent': true, ... } to AgentStatus array
    const agentMapping = [
      { id: 'packet', name: 'Packet Agent (C4)', key: 'packet_agent' },
      { id: 'flow', name: 'Flow Agent (C2)', key: 'flow_agent' },
      { id: 'behavior', name: 'Behavior Agent (C1)', key: 'behavior_agent' },
      { id: 'correlation', name: 'Correlation Agent (C3)', key: 'correlation_agent' },
      { id: 'response', name: 'Response Agent', key: 'response_agent' },
    ];

    return agentMapping.map(agent => 
      AgentStatusSchema.parse({
        id: agent.id,
        name: agent.name,
        status: loaded[agent.key] ? 'ONLINE' : 'OFFLINE',
        lastHeartbeat: new Date().toISOString(),
        eps: Math.floor(Math.random() * 500) + 100 // dummy live metric
      })
    );
  }
};

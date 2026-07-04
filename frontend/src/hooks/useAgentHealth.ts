import { useEffect } from 'react';
import { useAgentHealthStore } from '@stores/agent-health.store';
import { connectSocket } from '@lib/socket';
import { AgentStatusSchema } from '@/types/agent.types';

export const useAgentHealth = () => {
  const setAll = useAgentHealthStore((s) => s.setAllAgents);
  const update = useAgentHealthStore((s) => s.updateAgentStatus);

  useEffect(() => {
    const socket = connectSocket();
    const onHeartbeat = (payload: unknown) => {
      try {
        const parsed = AgentStatusSchema.parse(payload);
        update(parsed);
      } catch (err) {
        // ignore malformed
        // eslint-disable-next-line no-console
        console.warn('Malformed agent heartbeat', err);
      }
    };
    socket.on('agent:heartbeat', onHeartbeat);
    socket.connect();
    return () => {
      socket.off('agent:heartbeat', onHeartbeat);
      socket.disconnect();
    };
  }, [setAll, update]);
};

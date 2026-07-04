import { z } from 'zod';

export const AgentStatusSchema = z.object({
  id: z.string(),
  name: z.string(),
  status: z.enum(['ONLINE','DEGRADED','OFFLINE']),
  lastHeartbeat: z.string(),
  eps: z.number()
});

export type AgentStatus = z.infer<typeof AgentStatusSchema>;
export type AgentStatusList = AgentStatus[];

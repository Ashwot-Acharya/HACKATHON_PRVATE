import { z } from 'zod';

export const IncidentSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: z.enum(['CRITICAL','HIGH','MEDIUM','LOW']),
  status: z.enum(['OPEN','IN_PROGRESS','RESOLVED','FALSE_POSITIVE']),
  createdAt: z.string(),
  alerts: z.array(z.string())
});

export type Incident = z.infer<typeof IncidentSchema>;
export type IncidentList = { data: Incident[]; total: number };

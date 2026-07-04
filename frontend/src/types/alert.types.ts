import { z } from 'zod';

export const AlertSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  sourceIp: z.string(),
  destinationIp: z.string().optional(),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'QUEUED']),
  mitre: z.string().optional(),
  agents: z.array(z.string()),
  crs: z.number(),
  challenge: z.enum(['C1','C2','C3','C4']).optional(),
  label: z.string().optional(),
  is_suppressed: z.boolean().optional(),
  suppression_reason: z.string().optional(),
  raw_payload: z.any().optional()
});

export const AlertListSchema = z.object({
  data: z.array(AlertSchema),
  total: z.number(),
  page: z.number()
});

export type Alert = z.infer<typeof AlertSchema>;
export type AlertList = z.infer<typeof AlertListSchema>;

export type AlertFilters = {
  severity?: string[];
  agents?: string[];
  mitre?: string[];
  challenge?: string[];
  page?: number;
  perPage?: number;
};

import { z } from 'zod';

export const AuditEntrySchema = z.object({
  id: z.string(),
  ts: z.string(),
  user: z.string(),
  action: z.string(),
  details: z.record(z.unknown())
});

export const AuditListSchema = z.object({
  total: z.number(),
  page: z.number().optional(),
  data: z.array(AuditEntrySchema)
});

export type AuditEntry = z.infer<typeof AuditEntrySchema>;
export type AuditList = z.infer<typeof AuditListSchema>;

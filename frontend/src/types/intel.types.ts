import { z } from 'zod';

export const IntelFeedStatusSchema = z.object({
  name: z.string(),
  lastUpdated: z.string(),
  count: z.number(),
  status: z.enum(['LIVE', 'STALE', 'ERROR'])
});

export const IntelRefreshSchema = z.object({
  status: z.enum(['started'])
});

export type IntelFeedStatus = z.infer<typeof IntelFeedStatusSchema>;
export type IntelRefresh = z.infer<typeof IntelRefreshSchema>;

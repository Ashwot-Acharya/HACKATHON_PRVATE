import { z } from 'zod';

export const WSAlertNewSchema = z.object({
  event: z.literal('alert:new'),
  payload: z.object({ id: z.string(), timestamp: z.string() })
});

export type WSAlertNew = z.infer<typeof WSAlertNewSchema>;

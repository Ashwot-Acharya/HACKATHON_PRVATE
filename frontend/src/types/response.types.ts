import { z } from 'zod';

export const ActionResultSchema = z.object({
  actionId: z.string(),
  result: z.enum(['SUCCESS', 'FAILED'])
});

export type ActionResult = z.infer<typeof ActionResultSchema>;

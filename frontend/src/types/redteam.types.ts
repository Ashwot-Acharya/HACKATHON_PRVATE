import { z } from 'zod';

export const RedTeamScenarioSchema = z.object({
  id: z.string(),
  title: z.string(),
  challenge: z.enum(['C1', 'C2', 'C3', 'C4']),
  expectedSec: z.number()
});

export const RedTeamLaunchSchema = z.object({
  runId: z.string()
});

export const RedTeamResultSchema = z.object({
  detected: z.boolean(),
  detectionTimeSec: z.number(),
  challenges: z.array(z.enum(['C1', 'C2', 'C3', 'C4']))
});

export type RedTeamScenario = z.infer<typeof RedTeamScenarioSchema>;
export type RedTeamLaunch = z.infer<typeof RedTeamLaunchSchema>;
export type RedTeamResult = z.infer<typeof RedTeamResultSchema>;

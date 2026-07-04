import { z } from 'zod';
import { GraphSchema } from './graph.types';

export const DashboardKpiSchema = z.object({
  threatsToday: z.number(),
  falsePositiveRate: z.number(),
  intelFeedAgeMin: z.number().nullable().optional(),
  meanResponseTimeMs: z.number(),
  alertsSuppressed: z.number(),
  alertsEmitted: z.number(),
  suppressionRate: z.number(),
  activeRegime: z.string(),
  regimeDescription: z.string(),
  uptimeSeconds: z.number(),
  agentsOnline: z.number(),
  agentsTotal: z.number(),
  nepalTime: z.string(),
});

export const DashboardGraphSchema = GraphSchema;

export type DashboardKpis = z.infer<typeof DashboardKpiSchema>;
export type DashboardGraph = z.infer<typeof DashboardGraphSchema>;

import { apiClient } from '@lib/axios';
import { DashboardGraphSchema, DashboardKpiSchema } from '@/types/dashboard.types';

export const dashboardService = {
  getKpis: async () => {
    const res = await apiClient.get('/dashboard/kpis');
    return DashboardKpiSchema.parse({
      threatsToday: res.data.threats_today,
      falsePositiveRate: res.data.false_positive_rate,
      intelFeedAgeMin: res.data.intel_feed_age_min ?? null,
      meanResponseTimeMs: res.data.mean_response_time_ms,
      alertsSuppressed: res.data.alerts_suppressed,
      alertsEmitted: res.data.alerts_emitted,
      suppressionRate: res.data.suppression_rate,
      activeRegime: res.data.active_regime,
      regimeDescription: res.data.regime_description,
      uptimeSeconds: res.data.uptime_seconds,
      agentsOnline: res.data.agents_online,
      agentsTotal: res.data.agents_total,
      nepalTime: res.data.nepal_time,
    });
  },
  getGraph: async () => {
    const res = await apiClient.get('/dashboard/graph');
    return DashboardGraphSchema.parse(res.data);
  }
};

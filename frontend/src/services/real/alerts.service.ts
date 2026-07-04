import { AlertSchema, AlertListSchema } from '@/types/alert.types';
import type { AlertFilters } from '@/types/alert.types';

export const alertsService = {
  getAlerts: async (filters: AlertFilters) => {
    // Alerts are now fed live via WebSocket and stored in the Zustand alertStore.
    // This REST endpoint only returns an empty initial state.
    return AlertListSchema.parse({
      data: [],
      total: 0,
      page: filters.page || 1
    });
  },
  getAlertById: async (id: string) => {
    // For detailed view, the frontend pulls directly from the Zustand store.
    // We return a dummy fallback just in case this is called directly.
    return AlertSchema.parse({
        id: id,
        timestamp: new Date().toISOString(),
        sourceIp: "Unknown",
        destinationIp: "Unknown",
        severity: "LOW",
        mitre: "Unknown",
        agents: [],
        crs: 0.0,
        challenge: "C3"
    });
  }
};

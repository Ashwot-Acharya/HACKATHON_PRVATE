import { apiClient } from '@lib/axios';
import { IntelFeedStatusSchema, IntelRefreshSchema } from '@/types/intel.types';

export const intelService = {
  getFeeds: async () => {
    const res = await apiClient.get('/intel/status');
    const data = res.data;

    const lastUpdated = data.last_updated || new Date().toISOString();
    const ageMinutes = data.age_minutes ?? 0;

    // Determine status based on feed age (stale if > 60 min)
    const status = ageMinutes > 60 ? 'STALE' : 'LIVE';

    // Map backend counts to IntelFeedStatus array
    const feeds = [
      { name: 'JA3 Fingerprints', count: data.ja3_entries },
      { name: 'C2 IP Addresses', count: data.c2_ip_entries },
      { name: 'Tor Exit Nodes', count: data.tor_entries }
    ];

    return feeds.map(feed =>
      IntelFeedStatusSchema.parse({
        name: feed.name,
        lastUpdated: lastUpdated,
        count: feed.count,
        status: status
      })
    );
  },
  refresh: async () => {
    await apiClient.post('/intel/refresh');
    return IntelRefreshSchema.parse({ status: 'started' });
  }
};

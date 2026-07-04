import { apiClient } from '@lib/axios';

export const redteamService = {
  getScenarios: async () => {
    const res = await apiClient.get('/redteam/scenarios');
    return res.data;
  },
  runScenario: async (scenarioId: string) => {
    const res = await apiClient.post(`/redteam/${scenarioId}`);
    return res.data;
  }
};

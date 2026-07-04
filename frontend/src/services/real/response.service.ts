import { apiClient } from '@lib/axios';
import { ActionResultSchema } from '@/types/response.types';

/**
 * Response service — triggers automated containment via the backend's
 * POST /respond endpoint. The backend expects a CorrelationResultInput body.
 */
export const responseService = {
  /**
   * Execute a containment response for a given alert.
   * Constructs a minimal CorrelationResultInput from the alert data.
   */
  executeResponse: async (alertData: {
    recordId: number;
    srcIp: string;
    dstIp: string;
    crs: number;
    priority: string;
    agentsFired: string[];
  }) => {
    const res = await apiClient.post('/respond', {
      record_id: alertData.recordId,
      src_ip: alertData.srcIp,
      dst_ip: alertData.dstIp,
      crs: alertData.crs,
      bbn_posterior: alertData.crs, // approximate
      priority: alertData.priority,
      is_suppressed: false,
      suppression_reason: null,
      agent_scores: {},
      agents_fired: alertData.agentsFired,
    });
    return ActionResultSchema.parse(res.data);
  },

  // Convenience wrappers that call the same endpoint
  quarantine: async (alertId: string, reason?: string) => {
    // For now, trigger a generic response since backend doesn't support per-action endpoints
    return responseService.executeResponse({
      recordId: parseInt(alertId.replace('ALERT-', '')) || 0,
      srcIp: 'Unknown',
      dstIp: 'Unknown',
      crs: 0.9,
      priority: 'CRITICAL',
      agentsFired: [],
    });
  },
  blockIp: async (alertId: string, reason: string) => {
    return responseService.quarantine(alertId, reason);
  },
  suspendAccount: async (alertId: string, reason: string) => {
    return responseService.quarantine(alertId, reason);
  },
  snapshot: async (alertId: string, reason: string) => {
    return responseService.quarantine(alertId, reason);
  }
};

import { apiClient } from '@lib/axios';

export const auditService = {
  getLogs: async (filters: { page?: number; pageSize?: number } = {}) => {
    const res = await apiClient.get('/audit/logs', { params: { limit: filters.pageSize || 50 } });
    
    // The API returns a plain array of AuditLogEntry objects
    const rawLogs = Array.isArray(res.data) ? res.data : (res.data.logs || []);
    const mappedLogs = rawLogs.map((log: Record<string, unknown>, i: number) => ({
      id: i.toString(),
      timestamp: log.timestamp,
      actor: "BankSentinel IDS",
      action: log.action,
      resource: "ResponseAgent",
      status: log.status,
      details: "",
      ipAddress: "127.0.0.1",
      hash: log.hash
    }));

    return {
      data: mappedLogs,
      total: mappedLogs.length,
      page: filters.page || 1
    };
  },
  searchLogs: async () => {
    return auditService.getLogs();
  },
  downloadNrbReport: async () => {
    const res = await apiClient.get('/audit/nrb-report', { responseType: 'blob' });
    // Create a download link
    const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `NRB_Compliance_Report_${new Date().toISOString().slice(0, 10)}.pdf`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  },
  verifyChain: async () => {
    const res = await apiClient.get('/audit/verify');
    return res.data;
  }
};

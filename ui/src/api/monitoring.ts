import client from './client';

export interface AuditLogEntry {
  id: string;
  tenant_id: string | null;
  tenant_slug: string | null;
  user_id: string | null;
  agent_id: string | null;
  actor_email: string;
  action: string;
  resource_type: string;
  resource_id: string;
  ip_address: string;
  created_at: string;
}

export interface AuditLogsPage {
  logs: AuditLogEntry[];
  total: number;
  page: number;
  total_pages: number;
}

export interface StatsResult {
  logins_today: number;
  failed_logins_today: number;
  logouts_today: number;
  active_users_week: number;
  total_audit_events: number;
  recent_events: AuditLogEntry[];
}

export const monitoringApi = {
  getStats: () =>
    client.get<StatsResult>('/admin/stats'),

  getSystemStats: () =>
    client.get<StatsResult>('/admin/stats/system'),

  getAuditLogs: (params?: { action?: string; user_id?: string; page?: number; limit?: number }) =>
    client.get<AuditLogsPage>('/admin/audit-logs', { params }),

  getSystemAuditLogs: (params?: { action?: string; user_id?: string; page?: number; limit?: number }) =>
    client.get<AuditLogsPage>('/admin/audit-logs/system', { params }),

  getMyActivity: (params?: { page?: number }) =>
    client.get<AuditLogsPage>('/auth/my-activity', { params }),
};

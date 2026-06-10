import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { useAuth } from '../contexts/AuthContext';
import { monitoringApi, AuditLogEntry, StatsResult } from '../api/monitoring';

// ─── Action badge ───────────────────────────────────────────────────────────

const actionColor: Record<string, string> = {
  'auth.login':          'bg-green-100 text-green-800',
  'auth.login_failed':   'bg-red-100 text-red-800',
  'auth.logout':         'bg-gray-100 text-gray-600',
  'auth.register':       'bg-purple-100 text-purple-800',
  'auth.token_refresh':  'bg-blue-50 text-blue-600',
  'auth.password_reset_requested': 'bg-yellow-100 text-yellow-800',
  'auth.password_reset_completed': 'bg-yellow-100 text-yellow-800',
};
function actionBadge(action: string) {
  const cls = actionColor[action] ?? (action.startsWith('admin.') ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-600');
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {action}
    </span>
  );
}

function relativeTime(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ─── Stat card ───────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, accent }: { label: string; value: number; sub?: string; accent?: string }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6 flex flex-col gap-1">
      <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">{label}</p>
      <p className={`text-3xl font-bold ${accent ?? 'text-gray-900'}`}>{value.toLocaleString()}</p>
      {sub && <p className="text-xs text-gray-400">{sub}</p>}
    </div>
  );
}

// ─── Audit log table ─────────────────────────────────────────────────────────

function AuditTable({
  logs,
  showTenant = false,
  loading,
}: {
  logs: AuditLogEntry[];
  showTenant?: boolean;
  loading: boolean;
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center h-32 text-sm text-gray-400">
        Loading events…
      </div>
    );
  }
  if (!logs.length) {
    return (
      <div className="flex items-center justify-center h-32 text-sm text-gray-400">
        No events found.
      </div>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-100 text-sm">
        <thead>
          <tr className="text-left text-xs text-gray-500 uppercase tracking-wide">
            {showTenant && <th className="px-4 py-3 font-medium">Tenant</th>}
            <th className="px-4 py-3 font-medium">Actor</th>
            <th className="px-4 py-3 font-medium">Action</th>
            <th className="px-4 py-3 font-medium">Resource</th>
            <th className="px-4 py-3 font-medium">IP</th>
            <th className="px-4 py-3 font-medium text-right">When</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-50">
          {logs.map((e) => (
            <tr key={e.id} className="hover:bg-gray-50 transition-colors">
              {showTenant && (
                <td className="px-4 py-3 text-gray-500 font-mono text-xs">
                  {e.tenant_slug ?? '—'}
                </td>
              )}
              <td className="px-4 py-3">
                <span className="font-medium text-gray-900 truncate max-w-[160px] block">
                  {e.actor_email || <span className="text-gray-400 italic">system</span>}
                </span>
              </td>
              <td className="px-4 py-3">{actionBadge(e.action)}</td>
              <td className="px-4 py-3 text-gray-500 text-xs font-mono">
                {e.resource_type ? `${e.resource_type}` : '—'}
              </td>
              <td className="px-4 py-3 text-gray-400 font-mono text-xs">{e.ip_address || '—'}</td>
              <td className="px-4 py-3 text-right text-gray-400 whitespace-nowrap">
                <span title={new Date(e.created_at).toLocaleString()}>{relativeTime(e.created_at)}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Stats cards strip ────────────────────────────────────────────────────────

function StatsStrip({ stats }: { stats: StatsResult }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <StatCard label="Logins today" value={stats.logins_today} accent="text-green-600" />
      <StatCard
        label="Failed logins today"
        value={stats.failed_logins_today}
        accent={stats.failed_logins_today > 0 ? 'text-red-600' : 'text-gray-900'}
      />
      <StatCard label="Active users (7d)" value={stats.active_users_week} sub="unique users" />
      <StatCard label="Total events" value={stats.total_audit_events} sub="all time" />
    </div>
  );
}

// ─── Filter bar ──────────────────────────────────────────────────────────────

const ACTION_OPTIONS = [
  '', 'auth.login', 'auth.login_failed', 'auth.logout', 'auth.register',
  'auth.password_reset_requested', 'admin.user_created', 'admin.role_created',
  'admin.tenant_created',
];

function FilterBar({
  action, onAction, userId, onUserId,
}: {
  action: string; onAction: (v: string) => void;
  userId: string; onUserId: (v: string) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      <select
        value={action}
        onChange={e => onAction(e.target.value)}
        className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white text-gray-700 focus:outline-none focus:ring-2 focus:ring-brand-500"
      >
        <option value="">All actions</option>
        {ACTION_OPTIONS.filter(Boolean).map(a => (
          <option key={a} value={a}>{a}</option>
        ))}
      </select>
      <input
        type="text"
        placeholder="Filter by user ID…"
        value={userId}
        onChange={e => onUserId(e.target.value)}
        className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white text-gray-700 focus:outline-none focus:ring-2 focus:ring-brand-500 w-56"
      />
    </div>
  );
}

// ─── Super-admin view ────────────────────────────────────────────────────────

function SuperAdminView() {
  const [action, setAction] = useState('');
  const [userId, setUserId] = useState('');
  const [page, setPage] = useState(1);

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['system-stats'],
    queryFn: () => monitoringApi.getSystemStats().then(r => r.data),
  });

  const { data: logs, isLoading: logsLoading } = useQuery({
    queryKey: ['system-audit-logs', action, userId, page],
    queryFn: () =>
      monitoringApi.getSystemAuditLogs({
        action: action || undefined,
        user_id: userId || undefined,
        page,
        limit: 25,
      }).then(r => r.data),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">System Monitoring</h1>
          <p className="text-sm text-gray-500 mt-0.5">All tenants — super admin view</p>
        </div>
        <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-purple-100 text-purple-800">
          super_admin
        </span>
      </div>

      {statsLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="bg-white rounded-xl border border-gray-200 p-6 h-24 animate-pulse bg-gray-50" />
          ))}
        </div>
      ) : stats ? (
        <StatsStrip stats={stats} />
      ) : null}

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-gray-900">All Tenants — Audit Events</h2>
          <FilterBar action={action} onAction={v => { setAction(v); setPage(1); }} userId={userId} onUserId={v => { setUserId(v); setPage(1); }} />
        </div>
        <AuditTable logs={logs?.logs ?? []} showTenant loading={logsLoading} />
        {logs && logs.total_pages > 1 && (
          <div className="flex items-center justify-between px-6 py-3 border-t border-gray-100 text-sm text-gray-500">
            <span>{logs.total} total events</span>
            <div className="flex items-center gap-2">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="px-3 py-1 rounded border border-gray-200 hover:bg-gray-50 disabled:opacity-40">Prev</button>
              <span>Page {page} / {logs.total_pages}</span>
              <button onClick={() => setPage(p => Math.min(logs.total_pages, p + 1))} disabled={page === logs.total_pages}
                className="px-3 py-1 rounded border border-gray-200 hover:bg-gray-50 disabled:opacity-40">Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Admin view ───────────────────────────────────────────────────────────────

function AdminView() {
  const [action, setAction] = useState('');
  const [userId, setUserId] = useState('');
  const [page, setPage] = useState(1);

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['tenant-stats'],
    queryFn: () => monitoringApi.getStats().then(r => r.data),
  });

  const { data: logs, isLoading: logsLoading } = useQuery({
    queryKey: ['tenant-audit-logs', action, userId, page],
    queryFn: () =>
      monitoringApi.getAuditLogs({
        action: action || undefined,
        user_id: userId || undefined,
        page,
        limit: 25,
      }).then(r => r.data),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Monitoring</h1>
          <p className="text-sm text-gray-500 mt-0.5">Your tenant — admin view</p>
        </div>
        <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-blue-100 text-blue-800">
          admin
        </span>
      </div>

      {statsLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="bg-white rounded-xl border border-gray-200 p-6 h-24 animate-pulse bg-gray-50" />
          ))}
        </div>
      ) : stats ? (
        <StatsStrip stats={stats} />
      ) : null}

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-gray-900">Tenant Audit Events</h2>
          <FilterBar action={action} onAction={v => { setAction(v); setPage(1); }} userId={userId} onUserId={v => { setUserId(v); setPage(1); }} />
        </div>
        <AuditTable logs={logs?.logs ?? []} loading={logsLoading} />
        {logs && logs.total_pages > 1 && (
          <div className="flex items-center justify-between px-6 py-3 border-t border-gray-100 text-sm text-gray-500">
            <span>{logs.total} total events</span>
            <div className="flex items-center gap-2">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="px-3 py-1 rounded border border-gray-200 hover:bg-gray-50 disabled:opacity-40">Prev</button>
              <span>Page {page} / {logs.total_pages}</span>
              <button onClick={() => setPage(p => Math.min(logs.total_pages, p + 1))} disabled={page === logs.total_pages}
                className="px-3 py-1 rounded border border-gray-200 hover:bg-gray-50 disabled:opacity-40">Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── User (self) view ─────────────────────────────────────────────────────────

function UserView() {
  const { user } = useAuth();
  const [page, setPage] = useState(1);

  const { data: logs, isLoading } = useQuery({
    queryKey: ['my-activity', page],
    queryFn: () => monitoringApi.getMyActivity({ page }).then(r => r.data),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">My Activity</h1>
          <p className="text-sm text-gray-500 mt-0.5">{user?.email} — recent account events</p>
        </div>
        <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-gray-100 text-gray-600">
          user
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Total events</p>
          <p className="text-3xl font-bold text-gray-900 mt-1">{logs?.total ?? '—'}</p>
          <p className="text-xs text-gray-400 mt-1">all time</p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Last login</p>
          <p className="text-base font-semibold text-gray-900 mt-2 truncate">
            {logs?.logs.find(e => e.action === 'auth.login')
              ? relativeTime(logs.logs.find(e => e.action === 'auth.login')!.created_at)
              : '—'}
          </p>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Role</p>
          <p className="text-base font-semibold text-gray-900 mt-2">{user?.role || '—'}</p>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100">
          <h2 className="text-sm font-semibold text-gray-900">Recent Account Activity</h2>
        </div>
        <AuditTable logs={logs?.logs ?? []} loading={isLoading} />
        {logs && logs.total_pages > 1 && (
          <div className="flex items-center justify-between px-6 py-3 border-t border-gray-100 text-sm text-gray-500">
            <span>{logs.total} total events</span>
            <div className="flex items-center gap-2">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="px-3 py-1 rounded border border-gray-200 hover:bg-gray-50 disabled:opacity-40">Prev</button>
              <span>Page {page} / {logs.total_pages}</span>
              <button onClick={() => setPage(p => Math.min(logs.total_pages, p + 1))} disabled={page === logs.total_pages}
                className="px-3 py-1 rounded border border-gray-200 hover:bg-gray-50 disabled:opacity-40">Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Page entry ───────────────────────────────────────────────────────────────

export function MonitoringPage() {
  const { isSuperAdmin, isAdmin } = useAuth();

  return (
    <Layout>
      {isSuperAdmin ? <SuperAdminView /> : isAdmin ? <AdminView /> : <UserView />}
    </Layout>
  );
}

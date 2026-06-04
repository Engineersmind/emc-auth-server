import { useAuth } from '../contexts/AuthContext';
import { Layout } from '../components/Layout';

/**
 * Self-service account page for non-admin tenant users.
 * Shows their profile, role, permissions, and what they have access to.
 */
export function AccountPage() {
  const { user } = useAuth();

  return (
    <Layout>
      <div className="space-y-6 max-w-2xl">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">My Account</h1>
          <p className="text-sm text-gray-500 mt-1">
            Your profile and access details for this tenant.
          </p>
        </div>

        {/* Profile card */}
        <div className="bg-white rounded-xl border border-gray-200 divide-y divide-gray-100">
          <div className="px-6 py-4">
            <h2 className="text-sm font-semibold text-gray-900">Profile</h2>
          </div>
          <dl className="divide-y divide-gray-100">
            <div className="px-6 py-3 flex justify-between text-sm">
              <dt className="text-gray-500 w-32 shrink-0">Name</dt>
              <dd className="text-gray-900 font-medium">
                {[user?.first_name, user?.last_name].filter(Boolean).join(' ') || '—'}
              </dd>
            </div>
            <div className="px-6 py-3 flex justify-between text-sm">
              <dt className="text-gray-500 w-32 shrink-0">Email</dt>
              <dd className="text-gray-900 font-medium">{user?.email}</dd>
            </div>
            <div className="px-6 py-3 flex justify-between text-sm">
              <dt className="text-gray-500 w-32 shrink-0">Role</dt>
              <dd>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-brand-100 text-brand-800">
                  {user?.role || '—'}
                </span>
              </dd>
            </div>
            <div className="px-6 py-3 flex justify-between text-sm">
              <dt className="text-gray-500 w-32 shrink-0">Tenant ID</dt>
              <dd className="text-gray-500 font-mono text-xs">{user?.tenant_id}</dd>
            </div>
          </dl>
        </div>

        {/* Permissions */}
        <div className="bg-white rounded-xl border border-gray-200 divide-y divide-gray-100">
          <div className="px-6 py-4 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-900">Permissions</h2>
            <span className="text-xs text-gray-400">{user?.permissions?.length ?? 0} granted</span>
          </div>
          <div className="px-6 py-4">
            {user?.permissions && user.permissions.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {user.permissions.map(p => (
                  <span
                    key={p}
                    className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-gray-100 text-gray-700 border border-gray-200"
                  >
                    {p}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-400">No permissions assigned to your role.</p>
            )}
          </div>
        </div>

        {/* Access notice */}
        <div className="bg-amber-50 border border-amber-200 rounded-xl px-6 py-4">
          <div className="flex gap-3">
            <span className="text-amber-500 text-lg leading-none mt-0.5">⚠</span>
            <div>
              <p className="text-sm font-medium text-amber-800">Limited access</p>
              <p className="text-sm text-amber-700 mt-0.5">
                Your role (<span className="font-medium">{user?.role}</span>) does not have admin access.
                Contact your tenant administrator to manage users, roles, or API keys.
              </p>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}

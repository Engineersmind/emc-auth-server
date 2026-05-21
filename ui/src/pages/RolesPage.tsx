import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { rolesApi } from '../api/roles';

export function RolesPage() {
  const { data: roles, isLoading, isError } = useQuery({
    queryKey: ['roles'],
    queryFn: () => rolesApi.list().then(r => r.data),
  });

  const { data: allPermissions } = useQuery({
    queryKey: ['permissions'],
    queryFn: () => rolesApi.permissions().then(r => r.data),
  });

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-semibold text-gray-900">Roles & Permissions</h1>
        </div>

        {allPermissions && allPermissions.length > 0 && (
          <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
            <p className="text-sm font-medium text-blue-800 mb-2">System Permissions</p>
            <div className="flex flex-wrap gap-1.5">
              {allPermissions.map(p => (
                <span key={p} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-blue-100 text-blue-700">
                  {p}
                </span>
              ))}
            </div>
          </div>
        )}

        {isLoading && <div className="text-sm text-gray-500">Loading…</div>}
        {isError && <div className="text-sm text-red-600">Failed to load roles</div>}

        {roles && (
          <div className="space-y-3">
            {roles.map(role => (
              <div key={role.id} className="bg-white rounded-xl border border-gray-200 p-5">
                <div className="flex items-center justify-between mb-3">
                  <h2 className="text-sm font-semibold text-gray-900 font-mono">{role.name}</h2>
                  <span className="text-xs text-gray-400">
                    {role.permissions.length} permission{role.permissions.length !== 1 ? 's' : ''}
                  </span>
                </div>
                {role.permissions.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {role.permissions.map(p => (
                      <span key={p} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-gray-100 text-gray-600">
                        {p}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-gray-400">No permissions assigned</p>
                )}
              </div>
            ))}
            {roles.length === 0 && (
              <div className="text-center py-8 text-sm text-gray-500">
                No roles defined
              </div>
            )}
          </div>
        )}
      </div>
    </Layout>
  );
}

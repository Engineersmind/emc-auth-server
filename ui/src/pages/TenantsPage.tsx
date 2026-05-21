import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { useAuth } from '../contexts/AuthContext';
import { tenantsApi, CreateTenantRequest } from '../api/tenants';

function CreateTenantModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState<CreateTenantRequest>({ name: '', slug: '' });
  const [error, setError] = useState('');

  const { mutate, isPending } = useMutation({
    mutationFn: tenantsApi.create,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tenants'] });
      onClose();
    },
    onError: (e: any) => setError(e.response?.data?.message || 'Failed to create tenant'),
  });

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-md">
        <h2 className="text-lg font-semibold mb-4">Create Tenant</h2>
        {error && <div className="mb-3 text-sm text-red-600 bg-red-50 rounded-lg p-3">{error}</div>}
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="Acme Corp"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Slug</label>
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
              value={form.slug}
              onChange={e => setForm(f => ({ ...f, slug: e.target.value }))}
              placeholder="acme"
            />
          </div>
        </div>
        <div className="flex justify-end space-x-3 mt-6">
          <button onClick={onClose} className="text-sm text-gray-600 hover:text-gray-900 px-4 py-2">Cancel</button>
          <button
            onClick={() => mutate(form)}
            disabled={isPending || !form.name || !form.slug}
            className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 disabled:opacity-60 transition-colors"
          >
            {isPending ? 'Creating\u2026' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  );
}

export function TenantsPage() {
  const { user } = useAuth();
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);

  const { data, isLoading, isError } = useQuery({
    queryKey: ['tenants'],
    queryFn: () => tenantsApi.list().then(r => r.data),
  });

  const { mutate: deleteTenant } = useMutation({
    mutationFn: tenantsApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tenants'] }),
  });

  if (user?.role !== 'super_admin') {
    return (
      <Layout>
        <div className="text-center py-12 text-gray-500">
          Access denied \u2014 super admin only
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      {showCreate && <CreateTenantModal onClose={() => setShowCreate(false)} />}
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-semibold text-gray-900">Tenants</h1>
          <button
            onClick={() => setShowCreate(true)}
            className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 transition-colors"
          >
            + New Tenant
          </button>
        </div>

        {isLoading && <div className="text-sm text-gray-500">Loading\u2026</div>}
        {isError && <div className="text-sm text-red-600">Failed to load tenants</div>}

        {data && (
          <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Slug</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3" />
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-100">
                {data.map(tenant => (
                  <tr key={tenant.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 text-sm font-medium text-gray-900">{tenant.name}</td>
                    <td className="px-6 py-4 text-sm text-gray-500 font-mono">{tenant.slug}</td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {new Date(tenant.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4">
                      {tenant.deleted_at ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">Deleted</span>
                      ) : (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">Active</span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-right">
                      {!tenant.deleted_at && (
                        <button
                          onClick={() => {
                            if (confirm(`Delete tenant "${tenant.name}"?`)) {
                              deleteTenant(tenant.id);
                            }
                          }}
                          className="text-sm text-red-600 hover:text-red-800"
                        >
                          Delete
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Layout>
  );
}

import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { SearchInput } from '../components/SearchInput';
import { rolesApi, Permission, Role } from '../api/roles';
import { tenantsApi, Tenant, TenantRole } from '../api/tenants';

function Toast({ message, type, onClose }: { message: string; type: 'success' | 'error'; onClose: () => void }) {
  useEffect(() => {
    const t = setTimeout(onClose, 3500);
    return () => clearTimeout(t);
  }, [onClose]);
  return (
    <div className={`fixed bottom-4 right-4 z-50 flex items-center space-x-3 px-4 py-3 rounded-xl shadow-lg text-sm font-medium
      ${type === 'success' ? 'bg-green-50 border border-green-200 text-green-800' : 'bg-red-50 border border-red-200 text-red-800'}`}>
      <span>{type === 'success' ? '✓' : '✕'}</span>
      <span>{message}</span>
      <button onClick={onClose} className="ml-2 text-gray-400 hover:text-gray-600 text-base leading-none">×</button>
    </div>
  );
}

function RoleModal({
  allPermissions, editing, tenantId, tenantName, onClose, onSuccess, onError,
}: {
  allPermissions: Permission[];
  editing: Role | TenantRole | null;
  tenantId: string | null;
  tenantName?: string;
  onClose: () => void;
  onSuccess: (msg: string) => void;
  onError: (msg: string) => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(editing?.name ?? '');
  const [permSearch, setPermSearch] = useState('');
  const [selected, setSelected] = useState<Set<string>>(
    new Set(editing?.permissions.map(p => p.id) ?? [])
  );
  const [error, setError] = useState('');

  const toggle = (id: string) =>
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const filteredPerms = allPermissions.filter(p =>
    p.name.toLowerCase().includes(permSearch.toLowerCase())
  );

  const createMutation = useMutation({
    mutationFn: () =>
      tenantId
        ? tenantsApi.createRole(tenantId, { name: name.trim(), permission_ids: Array.from(selected) })
        : rolesApi.create({ name: name.trim(), permission_ids: Array.from(selected) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: tenantId ? ['tenant-roles', tenantId] : ['roles'] });
      onSuccess(`Role "${name.trim()}" created`);
      onClose();
    },
    onError: (e: any) => {
      const msg = e.response?.data?.message || e.response?.data?.error || 'Failed to create role';
      setError(msg);
      onError(msg);
    },
  });

  const updateMutation = useMutation({
    mutationFn: () =>
      tenantId
        ? tenantsApi.updateRolePermissions(tenantId, editing!.id, Array.from(selected))
        : rolesApi.updatePermissions(editing!.id, Array.from(selected)),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: tenantId ? ['tenant-roles', tenantId] : ['roles'] });
      onSuccess(`Permissions updated for "${editing!.name}"`);
      onClose();
    },
    onError: (e: any) => {
      const msg = e.response?.data?.message || e.response?.data?.error || 'Failed to update permissions';
      setError(msg);
      onError(msg);
    },
  });

  const isPending = createMutation.isPending || updateMutation.isPending;

  const handleSubmit = () => {
    if (!editing && !name.trim()) { setError('Role name is required'); return; }
    editing ? updateMutation.mutate() : createMutation.mutate();
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-lg">
        <h2 className="text-lg font-semibold mb-1">
          {editing ? `Edit permissions — ${editing.name}` : 'Create Role'}
        </h2>
        {tenantName && (
          <p className="text-xs text-gray-400 mb-4">
            in tenant: <span className="font-mono text-gray-500">{tenantName}</span>
          </p>
        )}
        {error && <div className="mb-3 text-sm text-red-600 bg-red-50 rounded-lg p-3">{error}</div>}
        <div className="space-y-4">
          {!editing && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Role name</label>
              <input
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. editor"
                autoFocus
                onKeyDown={e => e.key === 'Enter' && handleSubmit()}
              />
            </div>
          )}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Permissions
              <span className="ml-2 text-xs text-gray-400 font-normal">{selected.size} selected</span>
            </label>
            {allPermissions.length === 0 ? (
              <p className="text-sm text-gray-400 italic">
                No permissions defined for this tenant yet — create permissions first.
              </p>
            ) : (
              <>
                <input
                  className="w-full rounded-lg border border-gray-200 px-3 py-1.5 text-xs mb-2 focus:outline-none focus:ring-1 focus:ring-brand-400"
                  placeholder="Filter permissions…"
                  value={permSearch}
                  onChange={e => setPermSearch(e.target.value)}
                />
                <div className="grid grid-cols-2 gap-1.5 max-h-52 overflow-y-auto border border-gray-100 rounded-lg p-2">
                  {filteredPerms.map(p => (
                    <label key={p.id} className="flex items-center space-x-2 px-3 py-1.5 rounded-lg border border-gray-200 cursor-pointer hover:bg-gray-50">
                      <input type="checkbox" checked={selected.has(p.id)} onChange={() => toggle(p.id)} className="accent-brand-600" />
                      <span className="text-xs font-mono text-gray-700 truncate">{p.name}</span>
                    </label>
                  ))}
                  {filteredPerms.length === 0 && (
                    <p className="col-span-2 text-xs text-gray-400 text-center py-3">No matching permissions</p>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
        <div className="flex justify-end space-x-3 mt-6">
          <button onClick={onClose} className="text-sm text-gray-600 hover:text-gray-900 px-4 py-2">Cancel</button>
          <button
            onClick={handleSubmit}
            disabled={isPending}
            className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 disabled:opacity-60 transition-colors"
          >
            {isPending ? 'Saving…' : editing ? 'Save permissions' : 'Create role'}
          </button>
        </div>
      </div>
    </div>
  );
}

export function RolesPage() {
  const qc = useQueryClient();
  const [modal, setModal] = useState<'create' | Role | TenantRole | null>(null);
  const [selectedTenantId, setSelectedTenantId] = useState('');
  const [search, setSearch] = useState('');
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  const showToast = (message: string, type: 'success' | 'error' = 'success') =>
    setToast({ message, type });

  const { data: tenants = [] } = useQuery({
    queryKey: ['tenants'],
    queryFn: () => tenantsApi.list().then(r => r.data),
  });

  const { data: ownRoles, isLoading: ownLoading, isError: ownError } = useQuery({
    queryKey: ['roles'],
    queryFn: () => rolesApi.list().then(r => r.data),
    enabled: !selectedTenantId,
  });

  const { data: tenantRoles, isLoading: tenantLoading, isError: tenantError } = useQuery({
    queryKey: ['tenant-roles', selectedTenantId],
    queryFn: () => tenantsApi.listRoles(selectedTenantId).then(r => r.data),
    enabled: !!selectedTenantId,
  });

  const { data: ownPermissions = [] } = useQuery({
    queryKey: ['permissions'],
    queryFn: () => rolesApi.permissions().then(r => r.data),
    enabled: !selectedTenantId,
  });

  const { data: tenantPermissions = [] } = useQuery({
    queryKey: ['tenant-permissions', selectedTenantId],
    queryFn: () => tenantsApi.listPermissions(selectedTenantId).then(r => r.data),
    enabled: !!selectedTenantId,
  });

  const activePermissions = selectedTenantId ? tenantPermissions : ownPermissions;
  const allRoles: (Role | TenantRole)[] = selectedTenantId ? (tenantRoles ?? []) : (ownRoles ?? []);
  const isLoading = selectedTenantId ? tenantLoading : ownLoading;
  const isError = selectedTenantId ? tenantError : ownError;

  const displayRoles = allRoles.filter(r =>
    r.name.toLowerCase().includes(search.toLowerCase())
  );

  const { mutate: deleteRole } = useMutation({
    mutationFn: (role: Role | TenantRole) =>
      selectedTenantId
        ? tenantsApi.deleteRole(selectedTenantId, role.id)
        : rolesApi.delete(role.id),
    onSuccess: (_, role) => {
      qc.invalidateQueries({ queryKey: selectedTenantId ? ['tenant-roles', selectedTenantId] : ['roles'] });
      showToast(`Role "${role.name}" deleted`);
    },
    onError: () => showToast('Failed to delete role', 'error'),
  });

  const selectedTenant = tenants.find((t: Tenant) => t.id === selectedTenantId);

  return (
    <Layout>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
      {modal !== null && (
        <RoleModal
          allPermissions={activePermissions}
          editing={modal === 'create' ? null : modal}
          tenantId={selectedTenantId || null}
          tenantName={selectedTenant?.name}
          onClose={() => setModal(null)}
          onSuccess={msg => showToast(msg, 'success')}
          onError={msg => showToast(msg, 'error')}
        />
      )}

      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-gray-900">Roles & Permissions</h1>
            {selectedTenant && (
              <p className="text-sm text-gray-400 mt-0.5">
                Showing roles for <span className="font-medium text-gray-600">{selectedTenant.name}</span>
              </p>
            )}
          </div>
          <button
            onClick={() => setModal('create')}
            className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 transition-colors"
          >
            + New Role
          </button>
        </div>

        <div className="flex items-center space-x-3">
          <SearchInput
            value={search}
            onChange={val => { setSearch(val); }}
            placeholder="Search roles by name…"
          />
          <select
            value={selectedTenantId}
            onChange={e => { setSelectedTenantId(e.target.value); setSearch(''); }}
            className="rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            <option value="">My tenant (emc)</option>
            {tenants.map((t: Tenant) => (
              <option key={t.id} value={t.id}>{t.name} ({t.slug})</option>
            ))}
          </select>
        </div>

        {activePermissions.length > 0 && (
          <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
            <p className="text-sm font-medium text-blue-800 mb-2">
              Available permissions in <span className="font-mono">{selectedTenant?.name ?? 'emc'}</span>
              <span className="ml-2 text-xs font-normal text-blue-500">({activePermissions.length})</span>
            </p>
            <div className="flex flex-wrap gap-1.5">
              {activePermissions.map(p => (
                <span key={p.id} title={p.description}
                  className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-blue-100 text-blue-700 cursor-default">
                  {p.name}
                </span>
              ))}
            </div>
          </div>
        )}

        {isLoading && (
          <div className="flex items-center space-x-2 text-sm text-gray-500">
            <div className="animate-spin h-4 w-4 border-2 border-brand-500 border-t-transparent rounded-full" />
            <span>Loading roles…</span>
          </div>
        )}

        {isError && (
          <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg p-3">
            Failed to load roles. Make sure you have the required permissions.
          </div>
        )}

        {!isLoading && !isError && (
          <div className="space-y-3">
            {displayRoles.length === 0 ? (
              <div className="text-center py-12 bg-white rounded-xl border border-gray-200">
                <p className="text-sm text-gray-500">
                  {search
                    ? `No roles matching "${search}"`
                    : `No roles defined in ${selectedTenant?.name ?? 'this tenant'} yet`}
                </p>
                {!search && (
                  <button
                    onClick={() => setModal('create')}
                    className="mt-3 text-sm text-brand-600 hover:text-brand-800"
                  >
                    Create the first role →
                  </button>
                )}
              </div>
            ) : (
              displayRoles.map(role => (
                <div key={role.id} className="bg-white rounded-xl border border-gray-200 p-5">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-2">
                      <h2 className="text-sm font-semibold text-gray-900 font-mono">{role.name}</h2>
                      {role.is_system && (
                        <span className="text-xs px-1.5 py-0.5 bg-gray-100 text-gray-500 rounded">system</span>
                      )}
                      {selectedTenant && (
                        <span className="text-xs px-1.5 py-0.5 bg-indigo-50 text-indigo-400 rounded font-mono">
                          {selectedTenant.slug}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center space-x-3">
                      <span className="text-xs text-gray-400">
                        {role.permissions.length} permission{role.permissions.length !== 1 ? 's' : ''}
                      </span>
                      <button onClick={() => setModal(role)} className="text-xs text-brand-600 hover:text-brand-800">
                        Edit
                      </button>
                      {!role.is_system && (
                        <button
                          onClick={() => { if (confirm(`Delete role "${role.name}"?`)) deleteRole(role); }}
                          className="text-xs text-red-500 hover:text-red-700"
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </div>
                  {role.permissions.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {role.permissions.map(p => (
                        <span key={p.id} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-gray-100 text-gray-600">
                          {p.name}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-gray-400">No permissions assigned</p>
                  )}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </Layout>
  );
}

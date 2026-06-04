import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { rolesApi, Permission, Role } from '../api/roles';

function RoleModal({
  allPermissions,
  editing,
  onClose,
}: {
  allPermissions: Permission[];
  editing: Role | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(editing?.name ?? '');
  // Track selected permission IDs
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

  const createMutation = useMutation({
    mutationFn: () => rolesApi.create({ name: name.trim(), permission_ids: Array.from(selected) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['roles'] }); onClose(); },
    onError: (e: any) => setError(e.response?.data?.message || e.response?.data?.error || 'Failed to create role'),
  });

  const updateMutation = useMutation({
    mutationFn: () => rolesApi.updatePermissions(editing!.id, Array.from(selected)),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['roles'] }); onClose(); },
    onError: (e: any) => setError(e.response?.data?.message || e.response?.data?.error || 'Failed to update permissions'),
  });

  const isPending = createMutation.isPending || updateMutation.isPending;

  const handleSubmit = () => {
    if (!editing && !name.trim()) { setError('Role name is required'); return; }
    editing ? updateMutation.mutate() : createMutation.mutate();
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-lg">
        <h2 className="text-lg font-semibold mb-4">
          {editing ? `Edit permissions — ${editing.name}` : 'Create Role'}
        </h2>
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
              />
            </div>
          )}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Permissions
              <span className="ml-2 text-xs text-gray-400 font-normal">{selected.size} selected</span>
            </label>
            {allPermissions.length === 0 ? (
              <p className="text-sm text-gray-400">No permissions defined for this tenant</p>
            ) : (
              <div className="grid grid-cols-2 gap-1.5 max-h-52 overflow-y-auto">
                {allPermissions.map(p => (
                  <label
                    key={p.id}
                    className="flex items-center space-x-2 px-3 py-1.5 rounded-lg border border-gray-200 cursor-pointer hover:bg-gray-50"
                  >
                    <input
                      type="checkbox"
                      checked={selected.has(p.id)}
                      onChange={() => toggle(p.id)}
                      className="accent-brand-600"
                    />
                    <span className="text-xs font-mono text-gray-700 truncate">{p.name}</span>
                  </label>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="flex justify-end space-x-3 mt-6">
          <button onClick={onClose} className="text-sm text-gray-600 hover:text-gray-900 px-4 py-2">
            Cancel
          </button>
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
  const [modal, setModal] = useState<'create' | Role | null>(null);

  const { data: roles, isLoading, isError } = useQuery({
    queryKey: ['roles'],
    queryFn: () => rolesApi.list().then(r => r.data),
  });

  const { data: allPermissions = [] } = useQuery({
    queryKey: ['permissions'],
    queryFn: () => rolesApi.permissions().then(r => r.data),
  });

  const { mutate: deleteRole } = useMutation({
    mutationFn: rolesApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['roles'] }),
  });

  return (
    <Layout>
      {modal !== null && (
        <RoleModal
          allPermissions={allPermissions}
          editing={modal === 'create' ? null : modal}
          onClose={() => setModal(null)}
        />
      )}

      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-semibold text-gray-900">Roles & Permissions</h1>
          <button
            onClick={() => setModal('create')}
            className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 transition-colors"
          >
            + New Role
          </button>
        </div>

        {allPermissions.length > 0 && (
          <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
            <p className="text-sm font-medium text-blue-800 mb-2">
              System Permissions
              <span className="ml-2 text-xs font-normal text-blue-600">({allPermissions.length})</span>
            </p>
            <div className="flex flex-wrap gap-1.5">
              {allPermissions.map(p => (
                <span key={p.id} title={p.description} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-blue-100 text-blue-700 cursor-default">
                  {p.name}
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
                  <div className="flex items-center space-x-2">
                    <h2 className="text-sm font-semibold text-gray-900 font-mono">{role.name}</h2>
                    {role.is_system && (
                      <span className="text-xs px-1.5 py-0.5 bg-gray-100 text-gray-500 rounded">system</span>
                    )}
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="text-xs text-gray-400">
                      {role.permissions.length} permission{role.permissions.length !== 1 ? 's' : ''}
                    </span>
                    <button
                      onClick={() => setModal(role)}
                      className="text-xs text-brand-600 hover:text-brand-800"
                    >
                      Edit
                    </button>
                    {!role.is_system && (
                      <button
                        onClick={() => {
                          if (confirm(`Delete role "${role.name}"?`)) deleteRole(role.id);
                        }}
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
            ))}
            {roles.length === 0 && (
              <div className="text-center py-8 text-sm text-gray-500">No roles defined</div>
            )}
          </div>
        )}
      </div>
    </Layout>
  );
}

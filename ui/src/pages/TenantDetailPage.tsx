import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import {
  tenantsApi,
  CreateTenantPermissionRequest,
  CreateTenantRoleRequest,
  CreateTenantUserRequest,
} from '../api/tenants';
import type { Permission } from '../api/roles';

type Tab = 'permissions' | 'roles' | 'users';

// ─── Permissions Tab ─────────────────────────────────────────────────────────

function PermissionsTab({ tid }: { tid: string }) {
  const qc = useQueryClient();
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [error, setError] = useState('');

  const { data: permissions = [], isLoading } = useQuery({
    queryKey: ['tenant-permissions', tid],
    queryFn: () => tenantsApi.listPermissions(tid).then(r => r.data),
  });

  const { mutate: create, isPending: creating } = useMutation({
    mutationFn: (data: CreateTenantPermissionRequest) =>
      tenantsApi.createPermission(tid, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tenant-permissions', tid] });
      setNewName('');
      setNewDesc('');
      setError('');
    },
    onError: (e: any) =>
      setError(e.response?.data?.message || 'Failed to create permission'),
  });

  const { mutate: remove } = useMutation({
    mutationFn: (pid: string) => tenantsApi.deletePermission(tid, pid),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ['tenant-permissions', tid] }),
    onError: (e: any) =>
      setError(e.response?.data?.message || 'Failed to delete permission'),
  });

  return (
    <div className="space-y-5">
      {error && (
        <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      {/* Create */}
      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <h3 className="text-sm font-semibold text-gray-900 mb-3">Add Permission</h3>
        <div className="flex items-center space-x-2">
          <input
            type="text"
            value={newName}
            onChange={e => setNewName(e.target.value)}
            placeholder="e.g. reports:read"
            className="flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
          <input
            type="text"
            value={newDesc}
            onChange={e => setNewDesc(e.target.value)}
            placeholder="Description (optional)"
            className="flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
          <button
            onClick={() => create({ name: newName.trim(), description: newDesc.trim() || undefined })}
            disabled={creating || !newName.trim()}
            className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 disabled:opacity-60 transition-colors"
          >
            {creating ? 'Adding…' : 'Add'}
          </button>
        </div>
      </div>

      {/* List */}
      {isLoading && <div className="text-sm text-gray-500">Loading…</div>}
      {!isLoading && (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {permissions.map((p: Permission) => (
                <tr key={p.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 text-sm font-mono text-gray-900">{p.name}</td>
                  <td className="px-6 py-4 text-sm text-gray-500">{p.description || '—'}</td>
                  <td className="px-6 py-4 text-right">
                    <button
                      onClick={() => {
                        if (confirm(`Delete permission "${p.name}"?`)) remove(p.id);
                      }}
                      className="text-sm text-red-600 hover:text-red-800"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
              {permissions.length === 0 && (
                <tr>
                  <td colSpan={3} className="px-6 py-8 text-center text-sm text-gray-400">
                    No permissions defined
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Roles Tab ────────────────────────────────────────────────────────────────

function RolesTab({ tid }: { tid: string }) {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [newRoleName, setNewRoleName] = useState('');
  const [error, setError] = useState('');

  const { data: roles = [], isLoading } = useQuery({
    queryKey: ['tenant-roles', tid],
    queryFn: () => tenantsApi.listRoles(tid).then(r => r.data),
  });

  const { data: permissions = [] } = useQuery({
    queryKey: ['tenant-permissions', tid],
    queryFn: () => tenantsApi.listPermissions(tid).then(r => r.data),
  });

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const toggle = (id: string) =>
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const { mutate: create, isPending: creating } = useMutation({
    mutationFn: (data: CreateTenantRoleRequest) => tenantsApi.createRole(tid, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tenant-roles', tid] });
      setShowCreate(false);
      setNewRoleName('');
      setSelected(new Set());
      setError('');
    },
    onError: (e: any) =>
      setError(e.response?.data?.message || 'Failed to create role'),
  });

  const { mutate: remove } = useMutation({
    mutationFn: (rid: string) => tenantsApi.deleteRole(tid, rid),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tenant-roles', tid] }),
    onError: (e: any) =>
      setError(e.response?.data?.message || 'Failed to delete role'),
  });

  return (
    <div className="space-y-5">
      {error && (
        <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      <div className="flex justify-end">
        <button
          onClick={() => setShowCreate(v => !v)}
          className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 transition-colors"
        >
          {showCreate ? 'Cancel' : '+ New Role'}
        </button>
      </div>

      {showCreate && (
        <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-4">
          <h3 className="text-sm font-semibold text-gray-900">Create Role</h3>
          <input
            type="text"
            value={newRoleName}
            onChange={e => setNewRoleName(e.target.value)}
            placeholder="Role name (e.g. editor)"
            className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
          {permissions.length > 0 && (
            <div>
              <p className="text-xs font-medium text-gray-600 mb-2">
                Permissions <span className="text-gray-400">({selected.size} selected)</span>
              </p>
              <div className="grid grid-cols-2 gap-1.5 max-h-40 overflow-y-auto">
                {permissions.map((p: Permission) => (
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
            </div>
          )}
          <div className="flex justify-end">
            <button
              onClick={() =>
                create({ name: newRoleName.trim(), permission_ids: Array.from(selected) })
              }
              disabled={creating || !newRoleName.trim()}
              className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 disabled:opacity-60 transition-colors"
            >
              {creating ? 'Creating…' : 'Create'}
            </button>
          </div>
        </div>
      )}

      {isLoading && <div className="text-sm text-gray-500">Loading…</div>}
      {!isLoading && (
        <div className="space-y-3">
          {roles.map(role => (
            <div key={role.id} className="bg-white rounded-xl border border-gray-200 p-5">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center space-x-2">
                  <span className="text-sm font-semibold font-mono text-gray-900">{role.name}</span>
                  {role.is_system && (
                    <span className="text-xs px-1.5 py-0.5 bg-gray-100 text-gray-500 rounded">system</span>
                  )}
                </div>
                {!role.is_system && (
                  <button
                    onClick={() => {
                      if (confirm(`Delete role "${role.name}"?`)) remove(role.id);
                    }}
                    className="text-xs text-red-500 hover:text-red-700"
                  >
                    Delete
                  </button>
                )}
              </div>
              {role.permissions.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {role.permissions.map((p: Permission) => (
                    <span
                      key={p.id}
                      className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-gray-100 text-gray-600"
                    >
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
            <div className="text-center py-8 text-sm text-gray-400">No roles defined</div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Users Tab ────────────────────────────────────────────────────────────────

function UsersTab({ tid }: { tid: string }) {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<CreateTenantUserRequest>({
    email: '',
    password: '',
    first_name: '',
    last_name: '',
    role: 'user',
  });
  const [error, setError] = useState('');

  const { data: users = [], isLoading } = useQuery({
    queryKey: ['tenant-users', tid],
    queryFn: () => tenantsApi.listUsers(tid).then(r => r.data.users ?? []),
  });

  const { data: roles = [] } = useQuery({
    queryKey: ['tenant-roles', tid],
    queryFn: () => tenantsApi.listRoles(tid).then(r => r.data),
  });

  const { mutate: create, isPending: creating } = useMutation({
    mutationFn: (data: CreateTenantUserRequest) => tenantsApi.createUser(tid, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tenant-users', tid] });
      setShowCreate(false);
      setForm({ email: '', password: '', first_name: '', last_name: '', role: 'user' });
      setError('');
    },
    onError: (e: any) =>
      setError(e.response?.data?.message || 'Failed to create user'),
  });

  const { mutate: remove } = useMutation({
    mutationFn: (uid: string) => tenantsApi.deleteUser(tid, uid),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tenant-users', tid] }),
    onError: (e: any) =>
      setError(e.response?.data?.message || 'Failed to delete user'),
  });

  return (
    <div className="space-y-5">
      {error && (
        <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      <div className="flex justify-end">
        <button
          onClick={() => setShowCreate(v => !v)}
          className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 transition-colors"
        >
          {showCreate ? 'Cancel' : '+ New User'}
        </button>
      </div>

      {showCreate && (
        <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-3">
          <h3 className="text-sm font-semibold text-gray-900">Create User</h3>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">First name</label>
              <input
                value={form.first_name}
                onChange={e => setForm(f => ({ ...f, first_name: e.target.value }))}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Last name</label>
              <input
                value={form.last_name}
                onChange={e => setForm(f => ({ ...f, last_name: e.target.value }))}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Email</label>
            <input
              type="email"
              value={form.email}
              onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Password</label>
            <input
              type="password"
              value={form.password}
              onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Role</label>
            <select
              value={form.role}
              onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
            >
              {roles.length > 0
                ? roles.map(r => <option key={r.id} value={r.name}>{r.name}</option>)
                : ['user', 'admin', 'super_admin'].map(r => (
                    <option key={r} value={r}>{r}</option>
                  ))}
            </select>
          </div>
          <div className="flex justify-end">
            <button
              onClick={() => create(form)}
              disabled={creating || !form.email || !form.password}
              className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 disabled:opacity-60 transition-colors"
            >
              {creating ? 'Creating…' : 'Create User'}
            </button>
          </div>
        </div>
      )}

      {isLoading && <div className="text-sm text-gray-500">Loading…</div>}
      {!isLoading && (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Email</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Role</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {users.map(u => (
                <tr key={u.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 text-sm text-gray-900">
                    {u.first_name} {u.last_name}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-500">{u.email}</td>
                  <td className="px-6 py-4 text-sm font-mono text-gray-500">{u.role}</td>
                  <td className="px-6 py-4">
                    {u.deleted_at ? (
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                        Deleted
                      </span>
                    ) : (
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                        Active
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-right">
                    {!u.deleted_at && (
                      <button
                        onClick={() => {
                          if (confirm(`Delete user "${u.email}"?`)) remove(u.id);
                        }}
                        className="text-sm text-red-600 hover:text-red-800"
                      >
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-6 py-8 text-center text-sm text-gray-400">
                    No users
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export function TenantDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [tab, setTab] = useState<Tab>('permissions');

  const { data: tenant, isLoading } = useQuery({
    queryKey: ['tenant', id],
    queryFn: () =>
      tenantsApi.list().then(r => r.data.find(t => t.id === id) ?? null),
    enabled: !!id,
  });

  const tabs: { key: Tab; label: string }[] = [
    { key: 'permissions', label: 'Permissions' },
    { key: 'roles', label: 'Roles' },
    { key: 'users', label: 'Users' },
  ];

  return (
    <Layout>
      <div className="space-y-6">
        {/* Breadcrumb */}
        <div className="flex items-center space-x-2 text-sm">
          <Link to="/tenants" className="text-gray-500 hover:text-gray-700">
            ← Tenants
          </Link>
          {tenant && (
            <>
              <span className="text-gray-300">/</span>
              <span className="text-gray-900 font-medium">{tenant.name}</span>
              <span className="font-mono text-xs text-gray-400 bg-gray-100 px-1.5 py-0.5 rounded">
                {tenant.slug}
              </span>
            </>
          )}
        </div>

        {isLoading && <div className="text-sm text-gray-500">Loading…</div>}

        {id && (
          <>
            {/* Tabs */}
            <div className="border-b border-gray-200">
              <nav className="-mb-px flex space-x-6">
                {tabs.map(t => (
                  <button
                    key={t.key}
                    onClick={() => setTab(t.key)}
                    className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
                      tab === t.key
                        ? 'border-brand-600 text-brand-600'
                        : 'border-transparent text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </nav>
            </div>

            {/* Tab content */}
            {tab === 'permissions' && <PermissionsTab tid={id} />}
            {tab === 'roles' && <RolesTab tid={id} />}
            {tab === 'users' && <UsersTab tid={id} />}
          </>
        )}
      </div>
    </Layout>
  );
}

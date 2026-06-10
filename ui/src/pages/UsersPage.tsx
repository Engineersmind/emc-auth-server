import { useState } from 'react';
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { SearchInput } from '../components/SearchInput';
import { Pagination } from '../components/Pagination';
import { usersApi, CreateUserRequest } from '../api/users';
import { rolesApi } from '../api/roles';
import { tenantsApi, Tenant } from '../api/tenants';

function CreateUserModal({ onClose, tenantId }: { onClose: () => void; tenantId: string | null }) {
  const qc = useQueryClient();
  const [form, setForm] = useState<CreateUserRequest>({
    email: '',
    first_name: '',
    last_name: '',
    password: '',
    role: 'user',
  });
  const [error, setError] = useState('');

  const { data: roles = [] } = useQuery({
    queryKey: tenantId ? ['tenant-roles', tenantId] : ['roles'],
    queryFn: () => tenantId
      ? tenantsApi.listRoles(tenantId).then(r => r.data)
      : rolesApi.list().then(r => r.data),
  });

  const { mutate, isPending } = useMutation({
    mutationFn: (data: CreateUserRequest) => tenantId
      ? tenantsApi.createUser(tenantId, { ...data, first_name: data.first_name, last_name: data.last_name })
      : usersApi.create(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: tenantId ? ['tenant-users', tenantId] : ['users'] });
      onClose();
    },
    onError: (e: any) => setError(e.response?.data?.message || 'Failed to create user'),
  });

  const field = (label: string, key: keyof CreateUserRequest, type = 'text', placeholder = '') => (
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-1">{label}</label>
      <input
        type={type}
        className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
        value={form[key] as string}
        onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
        placeholder={placeholder}
      />
    </div>
  );

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-md">
        <h2 className="text-lg font-semibold mb-4">
          Create User{tenantId && <span className="ml-2 text-xs font-normal text-gray-400">in selected tenant</span>}
        </h2>
        {error && <div className="mb-3 text-sm text-red-600 bg-red-50 rounded-lg p-3">{error}</div>}
        <div className="space-y-3">
          {field('First name', 'first_name', 'text', 'Jane')}
          {field('Last name', 'last_name', 'text', 'Doe')}
          {field('Email', 'email', 'email', 'jane@example.com')}
          {field('Password', 'password', 'password', '••••••••')}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Role</label>
            <select
              className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
              value={form.role}
              onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
            >
              {roles.length > 0
                ? roles.map(r => <option key={r.id} value={r.name}>{r.name}</option>)
                : ['user', 'admin', 'super_admin', 'service'].map(r => (
                    <option key={r} value={r}>{r}</option>
                  ))}
            </select>
          </div>
        </div>
        <div className="flex justify-end space-x-3 mt-6">
          <button onClick={onClose} className="text-sm text-gray-600 hover:text-gray-900 px-4 py-2">
            Cancel
          </button>
          <button
            onClick={() => mutate(form)}
            disabled={isPending || !form.email || !form.password}
            className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 disabled:opacity-60 transition-colors"
          >
            {isPending ? 'Creating…' : 'Create user'}
          </button>
        </div>
      </div>
    </div>
  );
}

const ROLES = ['', 'super_admin', 'admin', 'user', 'service'];

export function UsersPage() {
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [selectedTenantId, setSelectedTenantId] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const LIMIT = 20;

  const { data: tenants = [] } = useQuery({
    queryKey: ['tenants'],
    queryFn: () => tenantsApi.list().then(r => r.data),
  });

  const serverQuery = useQuery({
    queryKey: ['users', page, search, roleFilter],
    queryFn: () =>
      usersApi.list({ page, limit: LIMIT, search: search || undefined, role: roleFilter || undefined })
        .then(r => r.data),
    placeholderData: keepPreviousData,
    enabled: !selectedTenantId,
  });

  const tenantUsersQuery = useQuery({
    queryKey: ['tenant-users', selectedTenantId],
    queryFn: () => tenantsApi.listUsers(selectedTenantId).then(r => r.data),
    enabled: !!selectedTenantId,
  });

  const filteredTenantUsers = (tenantUsersQuery.data ?? []).filter(u => {
    const matchesSearch = !search ||
      u.email.toLowerCase().includes(search.toLowerCase()) ||
      `${u.first_name} ${u.last_name}`.toLowerCase().includes(search.toLowerCase());
    const matchesRole = !roleFilter || u.role === roleFilter;
    return matchesSearch && matchesRole;
  });

  const paginatedTenantUsers = filteredTenantUsers.slice((page - 1) * LIMIT, page * LIMIT);

  const isLoading = selectedTenantId ? tenantUsersQuery.isLoading : serverQuery.isLoading;
  const isError = selectedTenantId ? tenantUsersQuery.isError : serverQuery.isError;

  const displayUsers = selectedTenantId
    ? paginatedTenantUsers
    : (serverQuery.data?.users ?? []);
  const totalUsers = selectedTenantId
    ? filteredTenantUsers.length
    : (serverQuery.data?.total ?? 0);

  const { mutate: deleteUser } = useMutation({
    mutationFn: (userId: string) => selectedTenantId
      ? tenantsApi.deleteUser(selectedTenantId, userId)
      : usersApi.delete(userId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: selectedTenantId ? ['tenant-users', selectedTenantId] : ['users'] });
    },
  });

  const handleSearchChange = (val: string) => { setSearch(val); setPage(1); };
  const handleRoleChange = (val: string) => { setRoleFilter(val); setPage(1); };
  const handleTenantChange = (val: string) => { setSelectedTenantId(val); setPage(1); };

  const showTenantColumn = !selectedTenantId;

  const tenantSlugMap = Object.fromEntries(tenants.map((t: Tenant) => [t.id, t.slug]));

  return (
    <Layout>
      {showCreate && <CreateUserModal onClose={() => setShowCreate(false)} tenantId={selectedTenantId || null} />}

      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-semibold text-gray-900">Users</h1>
          <button
            onClick={() => setShowCreate(true)}
            className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 transition-colors"
          >
            + New User
          </button>
        </div>

        <div className="flex items-center space-x-3">
          <SearchInput
            value={search}
            onChange={handleSearchChange}
            placeholder="Search by email or name…"
          />
          <select
            value={selectedTenantId}
            onChange={e => handleTenantChange(e.target.value)}
            className="rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            <option value="">All tenants</option>
            {tenants.map((t: Tenant) => (
              <option key={t.id} value={t.id}>{t.name} ({t.slug})</option>
            ))}
          </select>
          <select
            value={roleFilter}
            onChange={e => handleRoleChange(e.target.value)}
            className="rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            <option value="">All roles</option>
            {ROLES.filter(Boolean).map(r => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
        </div>

        {isLoading && <div className="text-sm text-gray-500">Loading…</div>}
        {isError && <div className="text-sm text-red-600">Failed to load users</div>}

        {(serverQuery.data || selectedTenantId) && !isLoading && !isError && (
          <>
            <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                    {showTenantColumn && (
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Tenant</th>
                    )}
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                    <th className="px-6 py-3" />
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-100">
                  {displayUsers.map(user => (
                    <tr key={user.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4">
                        <div className="text-sm font-medium text-gray-900">
                          {user.first_name} {user.last_name}
                        </div>
                        <div className="text-xs text-gray-500">{user.email}</div>
                      </td>
                      {showTenantColumn && (
                        <td className="px-6 py-4">
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-gray-100 text-gray-500">
                            {tenantSlugMap[(user as any).tenant_id] ?? '—'}
                          </span>
                        </td>
                      )}
                      <td className="px-6 py-4">
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                          {user.role}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        {user.deleted_at ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">Deleted</span>
                        ) : (
                          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">Active</span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-500">
                        {new Date(user.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <div className="flex items-center justify-end space-x-3">
                          <Link
                            to={`/users/${user.id}`}
                            className="text-sm text-brand-600 hover:text-brand-800"
                          >
                            View →
                          </Link>
                          {!user.deleted_at && (
                            <button
                              onClick={() => {
                                if (confirm(`Delete user "${user.email}"?`)) deleteUser(user.id);
                              }}
                              className="text-sm text-red-500 hover:text-red-700"
                            >
                              Delete
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {displayUsers.length === 0 && (
                    <tr>
                      <td colSpan={showTenantColumn ? 6 : 5} className="px-6 py-8 text-center text-sm text-gray-500">
                        No users found
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <Pagination
              page={page}
              total={totalUsers}
              limit={LIMIT}
              onPageChange={setPage}
            />
          </>
        )}
      </div>
    </Layout>
  );
}

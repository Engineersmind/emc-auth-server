import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { SearchInput } from '../components/SearchInput';
import { Pagination } from '../components/Pagination';
import { usersApi, CreateUserRequest } from '../api/users';
import { rolesApi } from '../api/roles';
import { tenantsApi, Tenant } from '../api/tenants';

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

function CreateUserModal({ onClose, tenantId, onSuccess, onError }: {
  onClose: () => void;
  tenantId: string | null;
  onSuccess: (msg: string) => void;
  onError: (msg: string) => void;
}) {
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
    onSuccess: (_, data) => {
      qc.invalidateQueries({ queryKey: tenantId ? ['tenant-users', tenantId] : ['users'] });
      onSuccess(`User "${data.email}" created successfully`);
      onClose();
    },
    onError: (e: any) => {
      const msg = e.response?.data?.message || e.response?.data?.error || 'Failed to create user';
      setError(msg);
      onError(msg);
    },
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
        <h2 className="text-lg font-semibold mb-1">Create User</h2>
        {tenantId && <p className="text-xs text-gray-400 mb-4">in selected tenant</p>}
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
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
  const showToast = (message: string, type: 'success' | 'error' = 'success') => setToast({ message, type });
  const LIMIT = 20;

  const { data: tenants = [] } = useQuery({
    queryKey: ['tenants'],
    queryFn: () => tenantsApi.list().then(r => r.data),
  });

  // All-tenants view: fetch every tenant's users in parallel and merge
  const allTenantsQuery = useQuery({
    queryKey: ['all-tenants-users', tenants.map((t: Tenant) => t.id).join(',')],
    queryFn: async () => {
      const results = await Promise.all(
        tenants.map(async (t: Tenant) => {
          const users = await tenantsApi.listUsers(t.id).then(r => r.data);
          return users.map(u => ({ ...u, _tenantId: t.id, _tenantSlug: t.slug, _tenantName: t.name }));
        })
      );
      return results.flat();
    },
    enabled: !selectedTenantId && tenants.length > 0,
  });

  // Single tenant view
  const tenantUsersQuery = useQuery({
    queryKey: ['tenant-users', selectedTenantId],
    queryFn: () => tenantsApi.listUsers(selectedTenantId).then(r =>
      r.data.map(u => {
        const t = tenants.find((x: Tenant) => x.id === selectedTenantId);
        return { ...u, _tenantId: selectedTenantId, _tenantSlug: t?.slug ?? '', _tenantName: t?.name ?? '' };
      })
    ),
    enabled: !!selectedTenantId,
  });

  const rawUsers = selectedTenantId
    ? (tenantUsersQuery.data ?? [])
    : (allTenantsQuery.data ?? []);

  const filteredUsers = rawUsers.filter(u => {
    const matchesSearch = !search ||
      u.email.toLowerCase().includes(search.toLowerCase()) ||
      `${u.first_name} ${u.last_name}`.toLowerCase().includes(search.toLowerCase());
    const matchesRole = !roleFilter || u.role === roleFilter;
    return matchesSearch && matchesRole;
  });

  const totalUsers = filteredUsers.length;
  const displayUsers = filteredUsers.slice((page - 1) * LIMIT, page * LIMIT);

  const isLoading = selectedTenantId ? tenantUsersQuery.isLoading : allTenantsQuery.isLoading;
  const isError = selectedTenantId ? tenantUsersQuery.isError : allTenantsQuery.isError;

  const { mutate: deleteUser } = useMutation({
    mutationFn: ({ userId, tenantId }: { userId: string; tenantId: string }) =>
      tenantsApi.deleteUser(tenantId, userId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['all-tenants-users'] });
      qc.invalidateQueries({ queryKey: ['tenant-users', selectedTenantId] });
      showToast('User deleted');
    },
    onError: () => showToast('Failed to delete user', 'error'),
  });

  const handleSearchChange = (val: string) => { setSearch(val); setPage(1); };
  const handleRoleChange = (val: string) => { setRoleFilter(val); setPage(1); };
  const handleTenantChange = (val: string) => { setSelectedTenantId(val); setSearch(''); setRoleFilter(''); setPage(1); };

  return (
    <Layout>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          tenantId={selectedTenantId || null}
          onSuccess={msg => showToast(msg, 'success')}
          onError={msg => showToast(msg, 'error')}
        />
      )}

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

        {isLoading && (
          <div className="flex items-center space-x-2 text-sm text-gray-500">
            <div className="animate-spin h-4 w-4 border-2 border-brand-500 border-t-transparent rounded-full" />
            <span>Loading users…</span>
          </div>
        )}
        {isError && <div className="text-sm text-red-600 bg-red-50 rounded-lg p-3">Failed to load users</div>}

        {!isLoading && !isError && (
          <>
            <div className="text-xs text-gray-400">{totalUsers} user{totalUsers !== 1 ? 's' : ''} found</div>
            <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                    {!selectedTenantId && (
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
                    <tr key={`${(user as any)._tenantId}-${user.id}`} className="hover:bg-gray-50">
                      <td className="px-6 py-4">
                        <div className="text-sm font-medium text-gray-900">
                          {user.first_name} {user.last_name}
                        </div>
                        <div className="text-xs text-gray-500">{user.email}</div>
                      </td>
                      {!selectedTenantId && (
                        <td className="px-6 py-4">
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-gray-100 text-gray-500">
                            {(user as any)._tenantSlug ?? '—'}
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
                          <Link to={`/users/${user.id}`} className="text-sm text-brand-600 hover:text-brand-800">
                            View →
                          </Link>
                          {!user.deleted_at && (
                            <button
                              onClick={() => {
                                if (confirm(`Delete user "${user.email}"?`))
                                  deleteUser({ userId: user.id, tenantId: (user as any)._tenantId });
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
                      <td colSpan={selectedTenantId ? 5 : 6} className="px-6 py-8 text-center text-sm text-gray-500">
                        {search ? `No users matching "${search}"` : 'No users found'}
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

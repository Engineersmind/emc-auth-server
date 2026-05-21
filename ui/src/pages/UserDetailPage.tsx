import { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { usersApi } from '../api/users';
import { rolesApi } from '../api/roles';

export function UserDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const { data: user, isLoading } = useQuery({
    queryKey: ['user', id],
    queryFn: () => usersApi.get(id!).then(r => r.data),
    enabled: !!id,
  });

  const { data: roles } = useQuery({
    queryKey: ['roles'],
    queryFn: () => rolesApi.list().then(r => r.data),
  });

  const [selectedRole, setSelectedRole] = useState('');
  const [resetSent, setResetSent] = useState(false);
  const [error, setError] = useState('');

  const { mutate: updateRole, isPending: updatingRole } = useMutation({
    mutationFn: (role: string) => usersApi.updateRole(id!, role),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['user', id] });
      qc.invalidateQueries({ queryKey: ['users'] });
      setError('');
    },
    onError: (e: any) => setError(e.response?.data?.message || 'Failed to update role'),
  });

  const { mutate: forceReset, isPending: resetting } = useMutation({
    mutationFn: () => usersApi.forcePasswordReset(id!),
    onSuccess: () => setResetSent(true),
    onError: (e: any) => setError(e.response?.data?.message || 'Failed to send reset'),
  });

  const { mutate: deleteUser, isPending: deleting } = useMutation({
    mutationFn: () => usersApi.delete(id!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] });
      navigate('/users');
    },
    onError: (e: any) => setError(e.response?.data?.message || 'Failed to delete user'),
  });

  if (isLoading) {
    return (
      <Layout>
        <div className="text-sm text-gray-500">Loading…</div>
      </Layout>
    );
  }

  if (!user) {
    return (
      <Layout>
        <div className="text-sm text-red-600">User not found</div>
      </Layout>
    );
  }

  const currentRole = selectedRole || user.role;

  return (
    <Layout>
      <div className="space-y-6 max-w-2xl">
        <div className="flex items-center space-x-3">
          <Link to="/users" className="text-sm text-gray-500 hover:text-gray-700">← Users</Link>
          <span className="text-gray-300">/</span>
          <span className="text-sm text-gray-900">{user.email}</span>
        </div>

        <h1 className="text-2xl font-semibold text-gray-900">
          {user.first_name} {user.last_name}
        </h1>

        {error && (
          <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        )}

        {/* User info */}
        <div className="bg-white rounded-xl border border-gray-200 divide-y divide-gray-100">
          {[
            { label: 'Email', value: user.email },
            { label: 'User ID', value: user.id },
            { label: 'Tenant ID', value: user.tenant_id },
            { label: 'Created', value: new Date(user.created_at).toLocaleString() },
            { label: 'Status', value: user.deleted_at ? 'Deleted' : 'Active' },
          ].map(({ label, value }) => (
            <div key={label} className="flex px-6 py-4">
              <dt className="text-sm font-medium text-gray-500 w-32 flex-shrink-0">{label}</dt>
              <dd className="text-sm text-gray-900 font-mono">{value}</dd>
            </div>
          ))}
        </div>

        {/* Role assignment */}
        {!user.deleted_at && (
          <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-4">
            <h2 className="text-sm font-semibold text-gray-900">Role</h2>
            <div className="flex items-center space-x-3">
              <select
                value={currentRole}
                onChange={e => setSelectedRole(e.target.value)}
                className="rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
              >
                {(roles ?? []).map(r => (
                  <option key={r.id} value={r.name}>{r.name}</option>
                ))}
                {/* Fallback options if roles endpoint not implemented */}
                {(!roles || roles.length === 0) && (
                  <>
                    <option value="super_admin">super_admin</option>
                    <option value="admin">admin</option>
                    <option value="user">user</option>
                    <option value="service">service</option>
                  </>
                )}
              </select>
              <button
                onClick={() => updateRole(currentRole)}
                disabled={updatingRole || currentRole === user.role}
                className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 disabled:opacity-60 transition-colors"
              >
                {updatingRole ? 'Saving…' : 'Save Role'}
              </button>
            </div>
          </div>
        )}

        {/* Actions */}
        {!user.deleted_at && (
          <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-4">
            <h2 className="text-sm font-semibold text-gray-900">Actions</h2>
            <div className="flex items-center space-x-4">
              <button
                onClick={() => forceReset()}
                disabled={resetting || resetSent}
                className="bg-yellow-50 hover:bg-yellow-100 border border-yellow-200 text-yellow-800 text-sm rounded-lg px-4 py-2 disabled:opacity-60 transition-colors"
              >
                {resetting ? 'Sending…' : resetSent ? 'Reset email sent ✓' : 'Force Password Reset'}
              </button>

              <button
                onClick={() => {
                  if (confirm(`Delete user "${user.email}"? This cannot be undone.`)) {
                    deleteUser();
                  }
                }}
                disabled={deleting}
                className="bg-red-50 hover:bg-red-100 border border-red-200 text-red-700 text-sm rounded-lg px-4 py-2 disabled:opacity-60 transition-colors"
              >
                {deleting ? 'Deleting…' : 'Delete User'}
              </button>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}

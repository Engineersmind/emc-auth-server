import { useState } from 'react';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { SearchInput } from '../components/SearchInput';
import { Pagination } from '../components/Pagination';
import { usersApi } from '../api/users';

const ROLES = ['', 'super_admin', 'admin', 'user', 'service'];

export function UsersPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const LIMIT = 20;

  const { data, isLoading, isError } = useQuery({
    queryKey: ['users', page, search, roleFilter],
    queryFn: () =>
      usersApi.list({ page, limit: LIMIT, search: search || undefined, role: roleFilter || undefined })
        .then(r => r.data),
    placeholderData: keepPreviousData,
  });

  const handleSearchChange = (val: string) => {
    setSearch(val);
    setPage(1);
  };

  const handleRoleChange = (val: string) => {
    setRoleFilter(val);
    setPage(1);
  };

  return (
    <Layout>
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold text-gray-900">Users</h1>

        <div className="flex items-center space-x-3">
          <SearchInput
            value={search}
            onChange={handleSearchChange}
            placeholder="Search by email or name\u2026"
          />
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

        {isLoading && <div className="text-sm text-gray-500">Loading\u2026</div>}
        {isError && <div className="text-sm text-red-600">Failed to load users</div>}

        {data && (
          <>
            <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                    <th className="px-6 py-3" />
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-100">
                  {data.users.map(user => (
                    <tr key={user.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4">
                        <div className="text-sm font-medium text-gray-900">
                          {user.first_name} {user.last_name}
                        </div>
                        <div className="text-xs text-gray-500">{user.email}</div>
                      </td>
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
                        <Link
                          to={`/users/${user.id}`}
                          className="text-sm text-brand-600 hover:text-brand-800"
                        >
                          View \u2192
                        </Link>
                      </td>
                    </tr>
                  ))}
                  {data.users.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-6 py-8 text-center text-sm text-gray-500">
                        No users found
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <Pagination
              page={page}
              total={data.total}
              limit={LIMIT}
              onPageChange={setPage}
            />
          </>
        )}
      </div>
    </Layout>
  );
}

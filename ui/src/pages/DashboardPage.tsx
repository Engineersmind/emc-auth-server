import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Layout } from '../components/Layout';

export function DashboardPage() {
  const { user, isAdmin, loading } = useAuth();

  if (!loading && !isAdmin) return <Navigate to="/account" replace />;

  return (
    <Layout>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Dashboard</h1>
          <p className="text-sm text-gray-500 mt-1">
            Welcome back, {user?.first_name || user?.email}
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-white rounded-xl border border-gray-200 p-6">
            <p className="text-sm font-medium text-gray-500">Tenant</p>
            <p className="mt-1 text-lg font-semibold text-gray-900 truncate">{user?.tenant_id}</p>
          </div>
          <div className="bg-white rounded-xl border border-gray-200 p-6">
            <p className="text-sm font-medium text-gray-500">Role</p>
            <p className="mt-1 text-lg font-semibold text-gray-900">{user?.role}</p>
          </div>
          <div className="bg-white rounded-xl border border-gray-200 p-6">
            <p className="text-sm font-medium text-gray-500">Permissions</p>
            <p className="mt-1 text-lg font-semibold text-gray-900">{user?.permissions.length ?? 0}</p>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6 mt-6">
          <h2 className="text-sm font-semibold text-gray-900 mb-3">Monitoring</h2>
          <div className="flex items-center space-x-6">
            <a
              href="/metrics"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-brand-600 hover:text-brand-800"
            >
              Prometheus Metrics &rarr;
            </a>
            <a
              href="/swagger/index.html"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-brand-600 hover:text-brand-800"
            >
              API Documentation &rarr;
            </a>
          </div>
        </div>
      </div>
    </Layout>
  );
}

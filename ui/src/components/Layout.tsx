import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export function Layout({ children }: { children: React.ReactNode }) {
  const { user, logout, isAdmin, isSuperAdmin } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-brand-900 text-white shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-8">
              <Link to={isAdmin ? '/dashboard' : '/account'} className="text-lg font-semibold tracking-tight">
                EMC Auth
              </Link>
              {isAdmin && (
                <Link to="/dashboard" className="text-sm hover:text-brand-100 transition-colors">Dashboard</Link>
              )}
              {isSuperAdmin && (
                <Link to="/tenants" className="text-sm hover:text-brand-100 transition-colors">Tenants</Link>
              )}
              {isAdmin && (
                <Link to="/users" className="text-sm hover:text-brand-100 transition-colors">Users</Link>
              )}
              {isAdmin && (
                <Link to="/roles" className="text-sm hover:text-brand-100 transition-colors">Roles</Link>
              )}
              {isAdmin && (
                <Link to="/api-keys" className="text-sm hover:text-brand-100 transition-colors">API Keys</Link>
              )}
              {isAdmin && (
                <Link to="/saml" className="text-sm hover:text-brand-100 transition-colors">SAML</Link>
              )}
              <Link to="/monitoring" className="text-sm hover:text-brand-100 transition-colors">Monitoring</Link>
              {!isAdmin && (
                <Link to="/account" className="text-sm hover:text-brand-100 transition-colors">My Account</Link>
              )}
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-brand-200">{user?.email}</span>
              <button
                onClick={handleLogout}
                className="text-sm bg-brand-700 hover:bg-brand-600 px-3 py-1.5 rounded transition-colors"
              >
                Sign out
              </button>
            </div>
          </div>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>
    </div>
  );
}

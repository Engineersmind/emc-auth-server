import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from './contexts/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';

// Lazy-loaded pages (added in 06-02, 06-03, 06-04)
import { lazy, Suspense } from 'react';
const TenantsPage = lazy(() => import('./pages/TenantsPage').then(m => ({ default: m.TenantsPage })));
const TenantDetailPage = lazy(() => import('./pages/TenantDetailPage').then(m => ({ default: m.TenantDetailPage })));
const UsersPage = lazy(() => import('./pages/UsersPage').then(m => ({ default: m.UsersPage })));
const UserDetailPage = lazy(() => import('./pages/UserDetailPage').then(m => ({ default: m.UserDetailPage })));
const RolesPage = lazy(() => import('./pages/RolesPage').then(m => ({ default: m.RolesPage })));
const ApiKeysPage = lazy(() => import('./pages/ApiKeysPage').then(m => ({ default: m.ApiKeysPage })));
const SamlPage = lazy(() => import('./pages/SamlPage').then(m => ({ default: m.SamlPage })));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
});

const PageLoader = () => (
  <div className="min-h-screen flex items-center justify-center">
    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-600" />
  </div>
);

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute>
                  <DashboardPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/tenants"
              element={
                <ProtectedRoute>
                  <Suspense fallback={<PageLoader />}>
                    <TenantsPage />
                  </Suspense>
                </ProtectedRoute>
              }
            />
            <Route
              path="/tenants/:id"
              element={
                <ProtectedRoute>
                  <Suspense fallback={<PageLoader />}>
                    <TenantDetailPage />
                  </Suspense>
                </ProtectedRoute>
              }
            />
            <Route
              path="/users"
              element={
                <ProtectedRoute>
                  <Suspense fallback={<PageLoader />}>
                    <UsersPage />
                  </Suspense>
                </ProtectedRoute>
              }
            />
            <Route
              path="/users/:id"
              element={
                <ProtectedRoute>
                  <Suspense fallback={<PageLoader />}>
                    <UserDetailPage />
                  </Suspense>
                </ProtectedRoute>
              }
            />
            <Route
              path="/roles"
              element={
                <ProtectedRoute>
                  <Suspense fallback={<PageLoader />}>
                    <RolesPage />
                  </Suspense>
                </ProtectedRoute>
              }
            />
            <Route
              path="/api-keys"
              element={
                <ProtectedRoute>
                  <Suspense fallback={<PageLoader />}>
                    <ApiKeysPage />
                  </Suspense>
                </ProtectedRoute>
              }
            />
            <Route
              path="/saml"
              element={
                <ProtectedRoute>
                  <Suspense fallback={<PageLoader />}>
                    <SamlPage />
                  </Suspense>
                </ProtectedRoute>
              }
            />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}

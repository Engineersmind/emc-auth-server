import axios from 'axios';

const client = axios.create({
  baseURL: '/api/v1',
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
});

// Read tenant slug dynamically — set after login, falls back to env then 'emc'
export function getActiveTenant(): string {
  return localStorage.getItem('tenantSlug')
    ?? import.meta.env.VITE_TENANT_SLUG
    ?? 'emc';
}

export function setActiveTenant(slug: string) {
  localStorage.setItem('tenantSlug', slug);
}

export function clearActiveTenant() {
  localStorage.removeItem('tenantSlug');
}

// Attach current tenant slug on every request
client.interceptors.request.use(config => {
  config.headers['X-Tenant-Slug'] = getActiveTenant();
  return config;
});

// Redirect to login on 401 (except auth bootstrap calls)
client.interceptors.response.use(
  response => response,
  error => {
    if (
      error.response?.status === 401 &&
      !error.config?.url?.includes('/auth/session') &&
      !error.config?.url?.includes('/auth/me') &&
      !error.config?.url?.includes('/auth/otp/') &&
      window.location.pathname !== '/login'
    ) {
      clearActiveTenant();
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default client;

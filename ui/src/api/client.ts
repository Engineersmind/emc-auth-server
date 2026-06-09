import axios from 'axios';

const client = axios.create({
  baseURL: '/api/v1',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    'X-Tenant-Slug': 'emc',
  },
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
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default client;

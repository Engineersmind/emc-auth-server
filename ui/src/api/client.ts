import axios from 'axios';

const client = axios.create({
  baseURL: '/api/v1',
  withCredentials: true, // send HttpOnly cookies automatically
  headers: {
    'Content-Type': 'application/json',
  },
});

// Intercept 401 — redirect to login (except the login call itself)
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (
      error.response?.status === 401 &&
      !error.config?.url?.includes('/auth/session')
    ) {
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default client;

import axios from 'axios';

const client = axios.create({
  baseURL: '/api/v1',
  withCredentials: true, // send HttpOnly cookies automatically
  headers: {
    'Content-Type': 'application/json',
  },
});

// Intercept 401 — redirect to login unless we are already on the login page
// or the request is an auth-bootstrap / TOTP call that handles 401 in-page.
// Guard by current page URL (not request URL) to prevent an infinite redirect
// loop: AuthContext calls /auth/me on every mount; on /login this returns 401,
// which without this guard would fire window.location.href='/login' again and again.
client.interceptors.response.use(
  (response) => response,
  (error) => {
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

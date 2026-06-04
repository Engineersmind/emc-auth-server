import React, { createContext, useContext, useEffect, useState } from 'react';
import { authApi, UserInfo } from '../api/auth';

interface AuthContextValue {
  user: UserInfo | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<{ requiresTotp: boolean; sessionId?: string }>;
  loginTotp: (sessionId: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    authApi.me()
      .then((r) => setUser(r.data))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  async function login(email: string, password: string) {
    const { data } = await authApi.login({ email, password });
    if (data.requires_totp) {
      return { requiresTotp: true, sessionId: data.totp_session_id };
    }
    // /auth/session sets an HttpOnly cookie but returns no user body — fetch /auth/me to hydrate state
    if (data.user) {
      setUser(data.user);
    } else {
      const me = await authApi.me();
      setUser(me.data);
    }
    return { requiresTotp: false };
  }

  async function loginTotp(sessionId: string, code: string) {
    const { data } = await authApi.loginTotp({ totp_session_id: sessionId, code });
    if (data.user) setUser(data.user);
  }

  async function logout() {
    await authApi.logout();
    setUser(null);
    window.location.href = '/login';
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, loginTotp, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

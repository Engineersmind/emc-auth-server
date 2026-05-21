import client from './client';

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  access_token?: string;
  requires_totp?: boolean;
  totp_session_id?: string;
  user?: UserInfo;
}

export interface TOTPLoginRequest {
  totp_session_id: string;
  code: string;
}

export interface UserInfo {
  user_id: string;
  tenant_id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: string;
  permissions: string[];
}

export const authApi = {
  login: (data: LoginRequest) =>
    client.post<LoginResponse>('/auth/session', data),

  loginTotp: (data: TOTPLoginRequest) =>
    client.post<LoginResponse>('/auth/otp/verify-login', data),

  logout: () => client.post('/auth/session/logout'),

  me: () => client.get<UserInfo>('/auth/me'),
};

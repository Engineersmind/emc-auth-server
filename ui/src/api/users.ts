import client from './client';

export interface User {
  id: string;
  tenant_id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: string;
  created_at: string;
  deleted_at: string | null;
}

export interface UsersListResponse {
  users: User[];
  total: number;
  page: number;
  limit: number;
}

export interface CreateUserRequest {
  email: string;
  first_name: string;
  last_name: string;
  password: string;
  role: string;
}

export const usersApi = {
  list: (params: { page?: number; limit?: number; search?: string; role?: string }) =>
    client.get<UsersListResponse>('/admin/users', { params }),

  create: (data: CreateUserRequest) =>
    client.post<User>('/admin/users', data),

  delete: (id: string) => client.delete(`/admin/users/${id}`),

  get: (id: string) => client.get<User>(`/admin/users/${id}`),

  updateRole: (id: string, role: string) =>
    client.put(`/admin/users/${id}/role`, { role }),

  forcePasswordReset: (id: string) =>
    client.post(`/admin/users/${id}/force-password-reset`),
};

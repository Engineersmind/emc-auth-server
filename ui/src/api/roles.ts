import client from './client';

export interface Role {
  id: string;
  name: string;
  permissions: string[];
  created_at: string;
}

export interface CreateRoleRequest {
  name: string;
  permissions: string[];
}

export const rolesApi = {
  list: () => client.get<Role[]>('/admin/roles'),

  create: (data: CreateRoleRequest) =>
    client.post<Role>('/admin/roles', data),

  permissions: () => client.get<string[]>('/admin/permissions'),
};

import client from './client';

export interface Permission {
  id: string;
  name: string;
  description: string;
  created_at: string;
}

export interface Role {
  id: string;
  name: string;
  is_system: boolean;
  permissions: Permission[];
  created_at: string;
}

export interface CreateRoleRequest {
  name: string;
  permission_ids: string[];
}

export const rolesApi = {
  list: () => client.get<Role[]>('/admin/roles'),

  create: (data: CreateRoleRequest) =>
    client.post<Role>('/admin/roles', data),

  delete: (id: string) => client.delete(`/admin/roles/${id}`),

  updatePermissions: (id: string, permission_ids: string[]) =>
    client.put(`/admin/roles/${id}/permissions`, { permission_ids }),

  permissions: () => client.get<Permission[]>('/admin/permissions'),
};

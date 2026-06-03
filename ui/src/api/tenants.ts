import client from './client';
import type { Permission } from './roles';

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  created_at: string;
  deleted_at: string | null;
}

export interface CreateTenantRequest {
  name: string;
  slug: string;
  jwt_secret?: string;
}

export interface UpdateTenantRequest {
  name?: string;
  jwt_secret?: string;
}

// Cross-tenant types (used in TenantDetailPage)
export interface TenantRole {
  id: string;
  name: string;
  is_system: boolean;
  permissions: Permission[];
  created_at: string;
}

export interface TenantUser {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: string;
  created_at: string;
  deleted_at: string | null;
}

export interface CreateTenantUserRequest {
  email: string;
  password: string;
  first_name: string;
  last_name: string;
  role: string;
}

export interface CreateTenantRoleRequest {
  name: string;
  permission_ids: string[];
}

export interface CreateTenantPermissionRequest {
  name: string;
  description?: string;
}

export const tenantsApi = {
  list: () => client.get<Tenant[]>('/admin/tenants'),
  create: (data: CreateTenantRequest) => client.post<Tenant>('/admin/tenants', data),
  update: (id: string, data: UpdateTenantRequest) => client.put<Tenant>(`/admin/tenants/${id}`, data),
  delete: (id: string) => client.delete(`/admin/tenants/${id}`),

  // Cross-tenant permission management
  listPermissions: (tid: string) =>
    client.get<Permission[]>(`/admin/tenants/${tid}/permissions`),
  createPermission: (tid: string, data: CreateTenantPermissionRequest) =>
    client.post<Permission>(`/admin/tenants/${tid}/permissions`, data),
  deletePermission: (tid: string, pid: string) =>
    client.delete(`/admin/tenants/${tid}/permissions/${pid}`),

  // Cross-tenant role management
  listRoles: (tid: string) =>
    client.get<TenantRole[]>(`/admin/tenants/${tid}/roles`),
  createRole: (tid: string, data: CreateTenantRoleRequest) =>
    client.post<TenantRole>(`/admin/tenants/${tid}/roles`, data),
  updateRolePermissions: (tid: string, rid: string, permission_ids: string[]) =>
    client.put(`/admin/tenants/${tid}/roles/${rid}/permissions`, { permission_ids }),
  deleteRole: (tid: string, rid: string) =>
    client.delete(`/admin/tenants/${tid}/roles/${rid}`),

  // Cross-tenant user management
  listUsers: (tid: string) =>
    client.get<TenantUser[]>(`/admin/tenants/${tid}/users`),
  createUser: (tid: string, data: CreateTenantUserRequest) =>
    client.post<TenantUser>(`/admin/tenants/${tid}/users`, data),
  deleteUser: (tid: string, uid: string) =>
    client.delete(`/admin/tenants/${tid}/users/${uid}`),
};

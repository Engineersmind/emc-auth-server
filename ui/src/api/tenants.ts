import client from './client';

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

export const tenantsApi = {
  list: () => client.get<Tenant[]>('/admin/tenants'),

  create: (data: CreateTenantRequest) =>
    client.post<Tenant>('/admin/tenants', data),

  update: (id: string, data: UpdateTenantRequest) =>
    client.put<Tenant>(`/admin/tenants/${id}`, data),

  delete: (id: string) => client.delete(`/admin/tenants/${id}`),
};

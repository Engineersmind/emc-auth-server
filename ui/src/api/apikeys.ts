import client from './client';

export interface ApiKey {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

export interface CreateApiKeyResponse {
  id: string;
  name: string;
  key: string;
  created_at: string;
}

export const apiKeysApi = {
  list: () => client.get<ApiKey[]>('/admin/api-keys'),
  create: (name: string) => client.post<CreateApiKeyResponse>('/admin/api-keys', { name }),
  revoke: (id: string) => client.delete(`/admin/api-keys/${id}`),
};

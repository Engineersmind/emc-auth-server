import client from './client';

export interface SamlConfig {
  id?: string;
  entity_id: string;
  sso_url: string;
  certificate: string;
}

export const samlApi = {
  get: () => client.get<SamlConfig>('/admin/saml-config'),
  update: (data: SamlConfig) => client.put<SamlConfig>('/admin/saml-config', data),
};

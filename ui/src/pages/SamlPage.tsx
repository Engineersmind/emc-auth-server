import { useEffect, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { samlApi, SamlConfig } from '../api/saml';

export function SamlPage() {
  const qc = useQueryClient();
  const [form, setForm] = useState<SamlConfig>({ entity_id: '', sso_url: '', certificate: '' });
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');

  const { data, isLoading } = useQuery({
    queryKey: ['saml-config'],
    queryFn: () => samlApi.get().then(r => r.data).catch(() => null),
  });

  useEffect(() => {
    if (data) setForm(data);
  }, [data]);

  const { mutate: save, isPending } = useMutation({
    mutationFn: () => samlApi.update(form),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['saml-config'] });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    },
    onError: (e: any) => setError(e.response?.data?.message || 'Failed to save SAML config'),
  });

  return (
    <Layout>
      <div className="space-y-6 max-w-2xl">
        <h1 className="text-2xl font-semibold text-gray-900">SAML Configuration</h1>
        <p className="text-sm text-gray-500">
          Configure the SAML 2.0 Identity Provider for your tenant. Contact your IdP administrator for the entity ID, SSO URL, and X.509 certificate.
        </p>

        {error && (
          <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        )}
        {saved && (
          <div className="rounded-lg bg-green-50 border border-green-200 px-4 py-3 text-sm text-green-700">
            SAML configuration saved successfully.
          </div>
        )}

        {isLoading ? (
          <div className="text-sm text-gray-500">Loading...</div>
        ) : (
          <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Entity ID</label>
              <input
                type="text"
                value={form.entity_id}
                onChange={e => setForm(f => ({ ...f, entity_id: e.target.value }))}
                placeholder="https://idp.example.com/saml/metadata"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">SSO URL</label>
              <input
                type="url"
                value={form.sso_url}
                onChange={e => setForm(f => ({ ...f, sso_url: e.target.value }))}
                placeholder="https://idp.example.com/saml/sso"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">X.509 Certificate</label>
              <textarea
                value={form.certificate}
                onChange={e => setForm(f => ({ ...f, certificate: e.target.value }))}
                placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'}
                rows={8}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div className="flex justify-end">
              <button
                onClick={() => save()}
                disabled={isPending}
                className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-5 py-2 disabled:opacity-60 transition-colors"
              >
                {isPending ? 'Saving...' : 'Save Configuration'}
              </button>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}

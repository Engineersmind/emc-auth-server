import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { apiKeysApi, CreateApiKeyResponse } from '../api/apikeys';

export function ApiKeysPage() {
  const qc = useQueryClient();
  const [newKeyName, setNewKeyName] = useState('');
  const [createdKey, setCreatedKey] = useState<CreateApiKeyResponse | null>(null);
  const [error, setError] = useState('');

  const { data: keys, isLoading } = useQuery({
    queryKey: ['api-keys'],
    queryFn: () => apiKeysApi.list().then(r => r.data),
  });

  const { mutate: create, isPending: creating } = useMutation({
    mutationFn: () => apiKeysApi.create(newKeyName),
    onSuccess: (r) => {
      setCreatedKey(r.data);
      setNewKeyName('');
      qc.invalidateQueries({ queryKey: ['api-keys'] });
    },
    onError: (e: any) => setError(e.response?.data?.message || 'Failed to create key'),
  });

  const { mutate: revoke } = useMutation({
    mutationFn: apiKeysApi.revoke,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys'] }),
    onError: (e: any) => setError(e.response?.data?.message || 'Failed to revoke key'),
  });

  return (
    <Layout>
      <div className="space-y-6 max-w-3xl">
        <h1 className="text-2xl font-semibold text-gray-900">API Keys</h1>

        {error && (
          <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        )}

        {/* One-time key reveal modal */}
        {createdKey && (
          <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
            <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-lg">
              <h2 className="text-lg font-semibold mb-2">API Key Created</h2>
              <p className="text-sm text-gray-500 mb-4">
                Copy this key now — it will not be shown again.
              </p>
              <div className="bg-gray-950 rounded-lg p-4 font-mono text-sm text-green-400 break-all select-all">
                {createdKey.key}
              </div>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(createdKey.key);
                }}
                className="mt-3 text-sm text-brand-600 hover:text-brand-800"
              >
                Copy to clipboard
              </button>
              <div className="flex justify-end mt-4">
                {/* Setting createdKey to null clears the modal and removes the
                    key from active state. The previous state value (including
                    the plaintext key string) may linger briefly in the React
                    fiber until GC. For higher sensitivity, store only the key
                    string in state (not the full response object) and zero it
                    before nulling: setCreatedKey(prev => prev ? {...prev, key: ''} : null). */}
                <button
                  onClick={() => setCreatedKey(null)}
                  className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2"
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Create new key */}
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-sm font-semibold text-gray-900 mb-3">Create API Key</h2>
          <div className="flex items-center space-x-3">
            <input
              type="text"
              value={newKeyName}
              onChange={e => setNewKeyName(e.target.value)}
              placeholder="Key name (e.g. ci-pipeline)"
              className="flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
            <button
              onClick={() => create()}
              disabled={creating || !newKeyName.trim()}
              className="bg-brand-600 hover:bg-brand-700 text-white text-sm rounded-lg px-4 py-2 disabled:opacity-60 transition-colors"
            >
              {creating ? 'Creating...' : 'Create'}
            </button>
          </div>
        </div>

        {/* Keys list */}
        {isLoading && <div className="text-sm text-gray-500">Loading...</div>}

        {keys && (
          <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Created</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Used</th>
                  <th className="px-6 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {keys.map(key => (
                  <tr key={key.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 text-sm font-medium text-gray-900">{key.name}</td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {new Date(key.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {key.last_used ? new Date(key.last_used).toLocaleString() : '\u2014'}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => {
                          if (confirm(`Revoke key "${key.name}"? This cannot be undone.`)) {
                            revoke(key.id);
                          }
                        }}
                        className="text-sm text-red-600 hover:text-red-800"
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
                {keys.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-6 py-8 text-center text-sm text-gray-500">
                      No API keys
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Layout>
  );
}

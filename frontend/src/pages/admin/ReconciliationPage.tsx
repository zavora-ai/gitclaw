// Reconciliation Page
// Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6

import { useState, useCallback } from 'react';
import { AdminLayout } from '../../components/AdminLayout';
import {
  scanDisconnectedRepos,
  reconnectRepo,
  deleteOrphanedDb,
  deleteOrphanedStorage,
} from '../../services/adminApi';
import type { ReconciliationScanResult, DisconnectedRepo } from '../../types/api';

export function ReconciliationPage() {
  const [scanResult, setScanResult] = useState<ReconciliationScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [reconnectForm, setReconnectForm] = useState<{ repoId: string; ownerId: string; name: string } | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<{ type: 'db' | 'storage'; repoId: string } | null>(null);

  const handleScan = useCallback(async () => {
    setScanning(true);
    setError(null);
    try {
      const result = await scanDisconnectedRepos();
      setScanResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to scan for disconnected repos');
    } finally {
      setScanning(false);
    }
  }, []);

  const handleReconnect = async () => {
    if (!reconnectForm) return;
    setActionLoading(reconnectForm.repoId);
    try {
      await reconnectRepo(reconnectForm.repoId, {
        ownerId: reconnectForm.ownerId,
        name: reconnectForm.name,
      });
      setReconnectForm(null);
      await handleScan();
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to reconnect repository');
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteDb = async (repoId: string) => {
    setActionLoading(repoId);
    try {
      await deleteOrphanedDb(repoId);
      setDeleteConfirm(null);
      await handleScan();
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete DB record');
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteStorage = async (repoId: string) => {
    setActionLoading(repoId);
    try {
      await deleteOrphanedStorage(repoId);
      setDeleteConfirm(null);
      await handleScan();
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete storage objects');
    } finally {
      setActionLoading(null);
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  return (
    <AdminLayout>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Data Reconciliation</h1>
          <p className="text-sm text-gray-400 mt-1">
            Scan for inconsistencies between database records and object storage
          </p>
        </div>
        <button
          onClick={handleScan}
          disabled={scanning}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 rounded transition-colors flex items-center gap-2"
        >
          {scanning ? (
            <>
              <span className="animate-spin">⟳</span>
              Scanning...
            </>
          ) : (
            <>
              🔍 Scan for Issues
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-900/50 border border-red-700 rounded text-red-300">
          {error}
        </div>
      )}

      {!scanResult && !scanning && (
        <div className="text-center py-12 text-gray-400">
          <p className="text-lg mb-2">No scan results yet</p>
          <p className="text-sm">Click "Scan for Issues" to check for data inconsistencies</p>
        </div>
      )}

      {scanResult && (
        <>
          {/* Summary */}
          <div className="mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
            <div className="flex gap-8">
              <div>
                <span className="text-2xl font-bold">{scanResult.dbOnly.length}</span>
                <span className="text-gray-400 ml-2">DB-only records</span>
              </div>
              <div>
                <span className="text-2xl font-bold">{scanResult.storageOnly.length}</span>
                <span className="text-gray-400 ml-2">Storage-only objects</span>
              </div>
            </div>
            {scanResult.dbOnly.length === 0 && scanResult.storageOnly.length === 0 && (
              <p className="mt-4 text-green-400">✓ No inconsistencies found</p>
            )}
          </div>

          {/* DB-Only Section */}
          {scanResult.dbOnly.length > 0 && (
            <div className="mb-6">
              <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
                <span className="text-yellow-400">⚠</span>
                Database Records Without Storage
              </h2>
              <p className="text-sm text-gray-400 mb-4">
                These repositories exist in the database but have no corresponding objects in storage.
                They may have been partially deleted or corrupted.
              </p>
              <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-900">
                    <tr>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Repository</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Owner</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Created</th>
                      <th className="px-4 py-3 text-right text-sm font-medium text-gray-400">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700">
                    {scanResult.dbOnly.map((repo: DisconnectedRepo) => (
                      <tr key={repo.repoId} className="hover:bg-gray-700/50">
                        <td className="px-4 py-3">
                          <div className="font-medium">{repo.name || 'Unknown'}</div>
                          <div className="text-sm text-gray-500 font-mono">{repo.repoId.slice(0, 8)}...</div>
                        </td>
                        <td className="px-4 py-3 text-sm">{repo.ownerName || '-'}</td>
                        <td className="px-4 py-3 text-sm text-gray-400">
                          {repo.createdAt ? new Date(repo.createdAt).toLocaleDateString() : '-'}
                        </td>
                        <td className="px-4 py-3 text-right">
                          {deleteConfirm?.type === 'db' && deleteConfirm.repoId === repo.repoId ? (
                            <div className="flex items-center justify-end gap-2">
                              <span className="text-sm text-gray-400">Delete DB record?</span>
                              <button
                                onClick={() => handleDeleteDb(repo.repoId)}
                                disabled={actionLoading === repo.repoId}
                                className="px-3 py-1 text-sm bg-red-600 hover:bg-red-700 disabled:bg-red-800 rounded transition-colors"
                              >
                                {actionLoading === repo.repoId ? '...' : 'Yes'}
                              </button>
                              <button
                                onClick={() => setDeleteConfirm(null)}
                                className="px-3 py-1 text-sm bg-gray-600 hover:bg-gray-500 rounded transition-colors"
                              >
                                No
                              </button>
                            </div>
                          ) : (
                            <button
                              onClick={() => setDeleteConfirm({ type: 'db', repoId: repo.repoId })}
                              className="px-3 py-1 text-sm bg-red-600 hover:bg-red-700 rounded transition-colors"
                            >
                              Delete Record
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Storage-Only Section */}
          {scanResult.storageOnly.length > 0 && (
            <div className="mb-6">
              <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
                <span className="text-yellow-400">⚠</span>
                Storage Objects Without Database Records
              </h2>
              <p className="text-sm text-gray-400 mb-4">
                These objects exist in storage but have no corresponding database record.
                You can reconnect them to a new DB record or delete the orphaned storage.
              </p>
              <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-900">
                    <tr>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Storage Prefix</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Objects</th>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Size</th>
                      <th className="px-4 py-3 text-right text-sm font-medium text-gray-400">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700">
                    {scanResult.storageOnly.map((repo: DisconnectedRepo) => (
                      <tr key={repo.repoId} className="hover:bg-gray-700/50">
                        <td className="px-4 py-3">
                          <div className="font-mono text-sm">{repo.repoId.slice(0, 12)}...</div>
                        </td>
                        <td className="px-4 py-3 text-sm">{repo.objectCount || 0} objects</td>
                        <td className="px-4 py-3 text-sm text-gray-400">
                          {formatBytes(repo.totalSizeBytes || 0)}
                        </td>
                        <td className="px-4 py-3 text-right">
                          {deleteConfirm?.type === 'storage' && deleteConfirm.repoId === repo.repoId ? (
                            <div className="flex items-center justify-end gap-2">
                              <span className="text-sm text-gray-400">Delete storage?</span>
                              <button
                                onClick={() => handleDeleteStorage(repo.repoId)}
                                disabled={actionLoading === repo.repoId}
                                className="px-3 py-1 text-sm bg-red-600 hover:bg-red-700 disabled:bg-red-800 rounded transition-colors"
                              >
                                {actionLoading === repo.repoId ? '...' : 'Yes'}
                              </button>
                              <button
                                onClick={() => setDeleteConfirm(null)}
                                className="px-3 py-1 text-sm bg-gray-600 hover:bg-gray-500 rounded transition-colors"
                              >
                                No
                              </button>
                            </div>
                          ) : (
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => setReconnectForm({ repoId: repo.repoId, ownerId: '', name: '' })}
                                className="px-3 py-1 text-sm bg-green-600 hover:bg-green-700 rounded transition-colors"
                              >
                                Reconnect
                              </button>
                              <button
                                onClick={() => setDeleteConfirm({ type: 'storage', repoId: repo.repoId })}
                                className="px-3 py-1 text-sm bg-red-600 hover:bg-red-700 rounded transition-colors"
                              >
                                Delete
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {/* Reconnect Modal */}
      {reconnectForm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 max-w-md w-full mx-4">
            <h2 className="text-xl font-bold mb-4">Reconnect Repository</h2>
            <p className="text-sm text-gray-400 mb-4">
              Create a new database record for the orphaned storage objects.
            </p>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Owner ID</label>
                <input
                  type="text"
                  value={reconnectForm.ownerId}
                  onChange={(e) => setReconnectForm({ ...reconnectForm, ownerId: e.target.value })}
                  placeholder="Enter owner ID..."
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Repository Name</label>
                <input
                  type="text"
                  value={reconnectForm.name}
                  onChange={(e) => setReconnectForm({ ...reconnectForm, name: e.target.value })}
                  placeholder="Enter repository name..."
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setReconnectForm(null)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleReconnect}
                disabled={!reconnectForm.ownerId || !reconnectForm.name || actionLoading === reconnectForm.repoId}
                className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-green-800 rounded transition-colors"
              >
                {actionLoading === reconnectForm.repoId ? 'Reconnecting...' : 'Reconnect'}
              </button>
            </div>
          </div>
        </div>
      )}
    </AdminLayout>
  );
}

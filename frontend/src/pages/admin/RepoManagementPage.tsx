// Repository Management Page
// Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 7.7

import { useState, useEffect, useCallback } from 'react';
import { AdminLayout } from '../../components/AdminLayout';
import { listRepos, deleteRepo, scanDisconnectedRepos } from '../../services/adminApi';
import type { AdminRepoDetails, PaginatedResponse, ReconciliationScanResult, DisconnectedRepo } from '../../types/api';

export function RepoManagementPage() {
  const [repos, setRepos] = useState<PaginatedResponse<AdminRepoDetails> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [disconnectedRepos, setDisconnectedRepos] = useState<Set<string>>(new Set());

  const fetchRepos = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listRepos({ page, perPage: 20, search: search || undefined });
      setRepos(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load repositories');
    } finally {
      setLoading(false);
    }
  }, [page, search]);

  const checkDisconnected = useCallback(async () => {
    try {
      const result: ReconciliationScanResult = await scanDisconnectedRepos();
      const dbOnlyIds = new Set(result.dbOnly.map((r: DisconnectedRepo) => r.repoId));
      setDisconnectedRepos(dbOnlyIds);
    } catch {
      // Silently fail - disconnected check is optional
    }
  }, []);

  useEffect(() => {
    fetchRepos();
    checkDisconnected();
  }, [fetchRepos, checkDisconnected]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchRepos();
  };

  const handleDelete = async (repoId: string) => {
    setActionLoading(repoId);
    try {
      await deleteRepo(repoId);
      setDeleteConfirm(null);
      await fetchRepos();
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete repository');
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
        <h1 className="text-2xl font-bold">Repository Management</h1>
      </div>

      {/* Search */}
      <form onSubmit={handleSearch} className="mb-6">
        <div className="flex gap-2">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name, owner, or ID..."
            className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <button
            type="submit"
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded transition-colors"
          >
            Search
          </button>
        </div>
      </form>

      {error && (
        <div className="mb-6 p-4 bg-red-900/50 border border-red-700 rounded text-red-300">
          {error}
        </div>
      )}

      {loading && !repos ? (
        <div className="text-gray-400">Loading repositories...</div>
      ) : repos ? (
        <>
          {/* Repos Table */}
          <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden mb-6">
            <table className="w-full">
              <thead className="bg-gray-900">
                <tr>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Repository</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Owner</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Stats</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Size</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Created</th>
                  <th className="px-4 py-3 text-right text-sm font-medium text-gray-400">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {repos.items.map((repo) => (
                  <tr key={repo.repoId} className="hover:bg-gray-700/50">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div>
                          <div className="font-medium flex items-center gap-2">
                            {repo.name}
                            {disconnectedRepos.has(repo.repoId) && (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-900/50 text-yellow-300">
                                ⚠ Disconnected
                              </span>
                            )}
                          </div>
                          <div className="text-sm text-gray-500 font-mono">{repo.repoId.slice(0, 8)}...</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm">{repo.ownerName}</td>
                    <td className="px-4 py-3 text-sm text-gray-400">
                      <div className="flex gap-3">
                        <span>⭐ {repo.starCount}</span>
                        <span>🔀 {repo.prCount}</span>
                        <span>🔧 {repo.ciRunCount}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-400">
                      <div>{repo.objectCount} objects</div>
                      <div>{formatBytes(repo.totalSizeBytes)}</div>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-400">
                      {new Date(repo.createdAt).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {deleteConfirm === repo.repoId ? (
                        <div className="flex items-center justify-end gap-2">
                          <span className="text-sm text-gray-400">Delete?</span>
                          <button
                            onClick={() => handleDelete(repo.repoId)}
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
                          onClick={() => setDeleteConfirm(repo.repoId)}
                          className="px-3 py-1 text-sm bg-red-600 hover:bg-red-700 rounded transition-colors"
                        >
                          Delete
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-400">
              Showing {repos.items.length} of {repos.total} repositories
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-3 py-1 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:text-gray-600 rounded transition-colors"
              >
                Previous
              </button>
              <span className="px-3 py-1 text-gray-400">
                Page {page} of {repos.totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(repos.totalPages, p + 1))}
                disabled={page >= repos.totalPages}
                className="px-3 py-1 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:text-gray-600 rounded transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        </>
      ) : null}
    </AdminLayout>
  );
}

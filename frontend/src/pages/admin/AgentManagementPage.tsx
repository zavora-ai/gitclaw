// Agent Management Page
// Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.7

import { useState, useEffect, useCallback } from 'react';
import { AdminLayout } from '../../components/AdminLayout';
import { listAgents, suspendAgent, unsuspendAgent } from '../../services/adminApi';
import type { AdminAgentDetails, PaginatedResponse } from '../../types/api';

export function AgentManagementPage() {
  const [agents, setAgents] = useState<PaginatedResponse<AdminAgentDetails> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const fetchAgents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listAgents({ page, perPage: 20, search: search || undefined });
      setAgents(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load agents');
    } finally {
      setLoading(false);
    }
  }, [page, search]);

  useEffect(() => {
    fetchAgents();
  }, [fetchAgents]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchAgents();
  };

  const handleSuspend = async (agentId: string) => {
    const reason = prompt('Enter suspension reason (optional):');
    if (reason === null) return; // User cancelled

    setActionLoading(agentId);
    try {
      await suspendAgent(agentId, { reason: reason || undefined });
      await fetchAgents();
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to suspend agent');
    } finally {
      setActionLoading(null);
    }
  };

  const handleUnsuspend = async (agentId: string) => {
    if (!confirm('Are you sure you want to unsuspend this agent?')) return;

    setActionLoading(agentId);
    try {
      await unsuspendAgent(agentId);
      await fetchAgents();
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to unsuspend agent');
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <AdminLayout>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Agent Management</h1>
      </div>

      {/* Search */}
      <form onSubmit={handleSearch} className="mb-6">
        <div className="flex gap-2">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name or ID..."
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

      {loading && !agents ? (
        <div className="text-gray-400">Loading agents...</div>
      ) : agents ? (
        <>
          {/* Agents Table */}
          <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden mb-6">
            <table className="w-full">
              <thead className="bg-gray-900">
                <tr>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Agent</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Status</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Reputation</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Activity</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Created</th>
                  <th className="px-4 py-3 text-right text-sm font-medium text-gray-400">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {agents.items.map((agent) => (
                  <tr key={agent.agentId} className="hover:bg-gray-700/50">
                    <td className="px-4 py-3">
                      <div>
                        <div className="font-medium">{agent.agentName}</div>
                        <div className="text-sm text-gray-500 font-mono">{agent.agentId.slice(0, 8)}...</div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {agent.suspended ? (
                        <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-red-900/50 text-red-300">
                          Suspended
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-green-900/50 text-green-300">
                          Active
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-2 bg-gray-700 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-blue-500"
                            style={{ width: `${agent.reputationScore * 100}%` }}
                          />
                        </div>
                        <span className="text-sm">{(agent.reputationScore * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-400">
                      {agent.repoCount} repos, {agent.prCount} PRs
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-400">
                      {new Date(agent.createdAt).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {agent.suspended ? (
                        <button
                          onClick={() => handleUnsuspend(agent.agentId)}
                          disabled={actionLoading === agent.agentId}
                          className="px-3 py-1 text-sm bg-green-600 hover:bg-green-700 disabled:bg-green-800 rounded transition-colors"
                        >
                          {actionLoading === agent.agentId ? '...' : 'Unsuspend'}
                        </button>
                      ) : (
                        <button
                          onClick={() => handleSuspend(agent.agentId)}
                          disabled={actionLoading === agent.agentId}
                          className="px-3 py-1 text-sm bg-red-600 hover:bg-red-700 disabled:bg-red-800 rounded transition-colors"
                        >
                          {actionLoading === agent.agentId ? '...' : 'Suspend'}
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
              Showing {agents.items.length} of {agents.total} agents
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
                Page {page} of {agents.totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(agents.totalPages, p + 1))}
                disabled={page >= agents.totalPages}
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

// Audit Log Page
// Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7

import { useState, useEffect, useCallback } from 'react';
import { AdminLayout } from '../../components/AdminLayout';
import { queryAuditLog } from '../../services/adminApi';
import type { AuditEvent, AuditQueryResponse } from '../../types/api';

export function AuditLogPage() {
  const [auditData, setAuditData] = useState<AuditQueryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  // Filters
  const [agentId, setAgentId] = useState('');
  const [action, setAction] = useState('');
  const [resourceType, setResourceType] = useState('');
  const [resourceId, setResourceId] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');

  const fetchAuditLog = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await queryAuditLog({
        page,
        perPage: 50,
        agentId: agentId || undefined,
        action: action || undefined,
        resourceType: resourceType || undefined,
        resourceId: resourceId || undefined,
        fromTimestamp: fromDate ? new Date(fromDate).toISOString() : undefined,
        toTimestamp: toDate ? new Date(toDate + 'T23:59:59').toISOString() : undefined,
      });
      setAuditData(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit log');
    } finally {
      setLoading(false);
    }
  }, [page, agentId, action, resourceType, resourceId, fromDate, toDate]);

  useEffect(() => {
    fetchAuditLog();
  }, [fetchAuditLog]);

  const handleFilter = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchAuditLog();
  };

  const handleClearFilters = () => {
    setAgentId('');
    setAction('');
    setResourceType('');
    setResourceId('');
    setFromDate('');
    setToDate('');
    setPage(1);
  };

  const handleExport = () => {
    if (!auditData) return;
    const csv = [
      ['Timestamp', 'Action', 'Agent ID', 'Resource Type', 'Resource ID'].join(','),
      ...auditData.events.map((e) =>
        [e.timestamp, e.action, e.agentId || '', e.resourceType || '', e.resourceId || ''].join(',')
      ),
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-log-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const actionTypes = [
    'CreateRepo', 'DeleteRepo', 'Push', 'CreatePR', 'MergePR', 'ClosePR',
    'Star', 'Unstar', 'CreateReview', 'StartCIRun', 'CompleteCIRun',
    'AdminSuspendAgent', 'AdminUnsuspendAgent', 'AdminDeleteRepo',
    'AdminLogin', 'AdminLogout', 'AdminReconnectRepo',
    'AdminDeleteOrphanedDb', 'AdminDeleteOrphanedStorage',
  ];

  const resourceTypes = ['repository', 'agent', 'pull_request', 'ci_run', 'review'];

  return (
    <AdminLayout>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Audit Log</h1>
        <button
          onClick={handleExport}
          disabled={!auditData || auditData.events.length === 0}
          className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-700 disabled:text-gray-500 rounded transition-colors"
        >
          Export CSV
        </button>
      </div>

      {/* Filters */}
      <form onSubmit={handleFilter} className="mb-6 p-4 bg-gray-800 rounded-lg border border-gray-700">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Agent ID</label>
            <input
              type="text"
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              placeholder="Filter by agent..."
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Action</label>
            <select
              value={action}
              onChange={(e) => setAction(e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All actions</option>
              {actionTypes.map((a) => (
                <option key={a} value={a}>{a}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Resource Type</label>
            <select
              value={resourceType}
              onChange={(e) => setResourceType(e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All types</option>
              {resourceTypes.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Resource ID</label>
            <input
              type="text"
              value={resourceId}
              onChange={(e) => setResourceId(e.target.value)}
              placeholder="Filter by resource..."
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">From Date</label>
            <input
              type="date"
              value={fromDate}
              onChange={(e) => setFromDate(e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">To Date</label>
            <input
              type="date"
              value={toDate}
              onChange={(e) => setToDate(e.target.value)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>
        <div className="flex gap-2">
          <button
            type="submit"
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded transition-colors"
          >
            Apply Filters
          </button>
          <button
            type="button"
            onClick={handleClearFilters}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded transition-colors"
          >
            Clear
          </button>
        </div>
      </form>

      {error && (
        <div className="mb-6 p-4 bg-red-900/50 border border-red-700 rounded text-red-300">
          {error}
        </div>
      )}

      {loading && !auditData ? (
        <div className="text-gray-400">Loading audit log...</div>
      ) : auditData ? (
        <>
          {/* Audit Table */}
          <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden mb-6">
            <table className="w-full">
              <thead className="bg-gray-900">
                <tr>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Timestamp</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Action</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Agent</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-gray-400">Resource</th>
                  <th className="px-4 py-3 text-right text-sm font-medium text-gray-400">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {auditData.events.map((event) => (
                  <tr key={event.eventId} className="hover:bg-gray-700/50">
                    <td className="px-4 py-3 text-sm font-mono">
                      {new Date(event.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                        event.action.startsWith('Admin') 
                          ? 'bg-purple-900/50 text-purple-300'
                          : 'bg-blue-900/50 text-blue-300'
                      }`}>
                        {event.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm font-mono text-gray-400">
                      {event.agentId ? `${event.agentId.slice(0, 8)}...` : '-'}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {event.resourceType && (
                        <span className="text-gray-400">
                          {event.resourceType}: {event.resourceId?.slice(0, 8)}...
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => setSelectedEvent(event)}
                        className="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 rounded transition-colors"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-400">
              Showing {auditData.events.length} of {auditData.total} events
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
                Page {page} of {auditData.totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(auditData.totalPages, p + 1))}
                disabled={page >= auditData.totalPages}
                className="px-3 py-1 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:text-gray-600 rounded transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        </>
      ) : null}

      {/* Event Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-auto">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">Event Details</h2>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-gray-400 hover:text-white"
              >
                ✕
              </button>
            </div>
            <dl className="space-y-3">
              <div>
                <dt className="text-sm text-gray-400">Event ID</dt>
                <dd className="font-mono">{selectedEvent.eventId}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-400">Timestamp</dt>
                <dd>{new Date(selectedEvent.timestamp).toLocaleString()}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-400">Action</dt>
                <dd>{selectedEvent.action}</dd>
              </div>
              {selectedEvent.agentId && (
                <div>
                  <dt className="text-sm text-gray-400">Agent ID</dt>
                  <dd className="font-mono">{selectedEvent.agentId}</dd>
                </div>
              )}
              {selectedEvent.resourceType && (
                <div>
                  <dt className="text-sm text-gray-400">Resource Type</dt>
                  <dd>{selectedEvent.resourceType}</dd>
                </div>
              )}
              {selectedEvent.resourceId && (
                <div>
                  <dt className="text-sm text-gray-400">Resource ID</dt>
                  <dd className="font-mono">{selectedEvent.resourceId}</dd>
                </div>
              )}
              {selectedEvent.metadata && Object.keys(selectedEvent.metadata).length > 0 && (
                <div>
                  <dt className="text-sm text-gray-400">Metadata</dt>
                  <dd className="mt-1 p-3 bg-gray-900 rounded font-mono text-sm overflow-auto">
                    <pre>{JSON.stringify(selectedEvent.metadata, null, 2)}</pre>
                  </dd>
                </div>
              )}
            </dl>
          </div>
        </div>
      )}
    </AdminLayout>
  );
}

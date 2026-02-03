// System Health Page
// Requirements: 5.1, 5.2, 5.3, 5.5, 5.6

import { useState, useEffect, useCallback } from 'react';
import { AdminLayout } from '../../components/AdminLayout';
import { getSystemHealth } from '../../services/adminApi';
import type { SystemHealth } from '../../types/api';

type HealthStatus = 'healthy' | 'degraded' | 'unhealthy';

function getStatusColor(status: HealthStatus): string {
  switch (status) {
    case 'healthy':
      return 'bg-green-500';
    case 'degraded':
      return 'bg-yellow-500';
    case 'unhealthy':
      return 'bg-red-500';
  }
}

function getStatusBg(status: HealthStatus): string {
  switch (status) {
    case 'healthy':
      return 'bg-green-900/30 border-green-700';
    case 'degraded':
      return 'bg-yellow-900/30 border-yellow-700';
    case 'unhealthy':
      return 'bg-red-900/30 border-red-700';
  }
}

export function SystemHealthPage() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);

  const fetchHealth = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getSystemHealth();
      setHealth(data);
      setLastChecked(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to check system health');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, [fetchHealth]);

  return (
    <AdminLayout>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">System Health</h1>
          {lastChecked && (
            <p className="text-sm text-gray-400 mt-1">
              Last checked: {lastChecked.toLocaleTimeString()}
            </p>
          )}
        </div>
        <button
          onClick={fetchHealth}
          disabled={loading}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 rounded transition-colors flex items-center gap-2"
        >
          {loading ? (
            <>
              <span className="animate-spin">⟳</span>
              Checking...
            </>
          ) : (
            <>
              ⟳ Refresh
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-900/50 border border-red-700 rounded text-red-300">
          {error}
        </div>
      )}

      {health && (
        <>
          {/* Overall Status */}
          <div className={`mb-6 p-6 rounded-lg border ${getStatusBg(health.overall)}`}>
            <div className="flex items-center gap-3">
              <div className={`w-4 h-4 rounded-full ${getStatusColor(health.overall)}`} />
              <div>
                <h2 className="text-xl font-semibold capitalize">
                  System {health.overall}
                </h2>
                <p className="text-sm text-gray-400">
                  {health.overall === 'healthy'
                    ? 'All systems operational'
                    : health.overall === 'degraded'
                    ? 'Some components experiencing issues'
                    : 'Critical issues detected'}
                </p>
              </div>
            </div>
          </div>

          {/* Component Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Database Health */}
            <div className={`p-6 rounded-lg border ${getStatusBg(health.database.status)}`}>
              <div className="flex items-center gap-3 mb-4">
                <div className={`w-3 h-3 rounded-full ${getStatusColor(health.database.status)}`} />
                <h3 className="text-lg font-semibold">Database</h3>
              </div>
              <dl className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <dt className="text-gray-400">Status</dt>
                  <dd className="capitalize">{health.database.status}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-400">Latency</dt>
                  <dd>{health.database.latencyMs}ms</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-400">Pool Size</dt>
                  <dd>{health.database.poolSize}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-400">Active Connections</dt>
                  <dd>{health.database.activeConnections}</dd>
                </div>
              </dl>
              {health.database.error && (
                <div className="mt-4 p-3 bg-red-900/50 rounded text-sm text-red-300">
                  {health.database.error}
                </div>
              )}
            </div>

            {/* Object Storage Health */}
            <div className={`p-6 rounded-lg border ${getStatusBg(health.objectStorage.status)}`}>
              <div className="flex items-center gap-3 mb-4">
                <div className={`w-3 h-3 rounded-full ${getStatusColor(health.objectStorage.status)}`} />
                <h3 className="text-lg font-semibold">Object Storage (S3)</h3>
              </div>
              <dl className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <dt className="text-gray-400">Status</dt>
                  <dd className="capitalize">{health.objectStorage.status}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-400">Bucket</dt>
                  <dd className="font-mono text-xs">{health.objectStorage.bucket || '-'}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-400">Accessible</dt>
                  <dd>{health.objectStorage.accessible ? '✓ Yes' : '✗ No'}</dd>
                </div>
              </dl>
              {health.objectStorage.error && (
                <div className="mt-4 p-3 bg-red-900/50 rounded text-sm text-red-300">
                  {health.objectStorage.error}
                </div>
              )}
            </div>

            {/* Outbox Health */}
            <div className={`p-6 rounded-lg border ${getStatusBg(health.outbox.status)}`}>
              <div className="flex items-center gap-3 mb-4">
                <div className={`w-3 h-3 rounded-full ${getStatusColor(health.outbox.status)}`} />
                <h3 className="text-lg font-semibold">Event Outbox</h3>
              </div>
              <dl className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <dt className="text-gray-400">Status</dt>
                  <dd className="capitalize">{health.outbox.status}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-400">Pending Events</dt>
                  <dd>{health.outbox.pendingCount}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-gray-400">Failed Events</dt>
                  <dd className={health.outbox.failedCount > 0 ? 'text-red-400' : ''}>
                    {health.outbox.failedCount}
                  </dd>
                </div>
                {health.outbox.oldestPendingAge && (
                  <div className="flex justify-between">
                    <dt className="text-gray-400">Oldest Pending</dt>
                    <dd>{health.outbox.oldestPendingAge}s ago</dd>
                  </div>
                )}
              </dl>
              {health.outbox.error && (
                <div className="mt-4 p-3 bg-red-900/50 rounded text-sm text-red-300">
                  {health.outbox.error}
                </div>
              )}
            </div>
          </div>

          {/* Health Legend */}
          <div className="mt-8 p-4 bg-gray-800 rounded-lg border border-gray-700">
            <h3 className="text-sm font-medium text-gray-400 mb-3">Status Legend</h3>
            <div className="flex gap-6 text-sm">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-green-500" />
                <span>Healthy - Operating normally</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-yellow-500" />
                <span>Degraded - Experiencing issues</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <span>Unhealthy - Critical failure</span>
              </div>
            </div>
          </div>
        </>
      )}
    </AdminLayout>
  );
}

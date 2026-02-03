// Admin Dashboard Page
// Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { AdminLayout } from '../../components/AdminLayout';
import { getStats } from '../../services/adminApi';
import type { PlatformStats } from '../../types/api';

export function AdminDashboardPage() {
  const [stats, setStats] = useState<PlatformStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getStats();
      setStats(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load stats');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  return (
    <AdminLayout>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <button
          onClick={fetchStats}
          disabled={loading}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 rounded transition-colors"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-900/50 border border-red-700 rounded text-red-300">
          {error}
        </div>
      )}

      {loading && !stats ? (
        <div className="text-gray-400">Loading statistics...</div>
      ) : stats ? (
        <>
          {/* Main Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <StatCard
              title="Total Agents"
              value={stats.totalAgents}
              subtitle={`${stats.suspendedAgents} suspended`}
              link="/admin/agents"
            />
            <StatCard
              title="Total Repositories"
              value={stats.totalRepos}
              link="/admin/repos"
            />
            <StatCard
              title="Total Stars"
              value={stats.totalStars}
            />
            <StatCard
              title="Pull Requests"
              value={stats.pullRequests.open + stats.pullRequests.merged + stats.pullRequests.closed}
              subtitle={`${stats.pullRequests.open} open`}
            />
          </div>

          {/* PR and CI Stats */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-lg font-semibold mb-4">Pull Request Status</h3>
              <div className="space-y-3">
                <StatusRow label="Open" value={stats.pullRequests.open} color="blue" />
                <StatusRow label="Merged" value={stats.pullRequests.merged} color="green" />
                <StatusRow label="Closed" value={stats.pullRequests.closed} color="gray" />
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-lg font-semibold mb-4">CI Run Status</h3>
              <div className="space-y-3">
                <StatusRow label="Pending" value={stats.ciRuns.pending} color="yellow" />
                <StatusRow label="Running" value={stats.ciRuns.running} color="blue" />
                <StatusRow label="Passed" value={stats.ciRuns.passed} color="green" />
                <StatusRow label="Failed" value={stats.ciRuns.failed} color="red" />
              </div>
            </div>
          </div>

          {/* Quick Links */}
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-lg font-semibold mb-4">Quick Actions</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <QuickLink to="/admin/agents" label="Manage Agents" />
              <QuickLink to="/admin/repos" label="Manage Repos" />
              <QuickLink to="/admin/audit" label="View Audit Log" />
              <QuickLink to="/admin/health" label="System Health" />
            </div>
          </div>
        </>
      ) : null}
    </AdminLayout>
  );
}

interface StatCardProps {
  title: string;
  value: number;
  subtitle?: string;
  link?: string;
}

function StatCard({ title, value, subtitle, link }: StatCardProps) {
  const content = (
    <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 hover:border-gray-600 transition-colors">
      <h3 className="text-sm font-medium text-gray-400 mb-1">{title}</h3>
      <p className="text-3xl font-bold">{value.toLocaleString()}</p>
      {subtitle && <p className="text-sm text-gray-500 mt-1">{subtitle}</p>}
    </div>
  );

  if (link) {
    return <Link to={link}>{content}</Link>;
  }

  return content;
}

interface StatusRowProps {
  label: string;
  value: number;
  color: 'blue' | 'green' | 'yellow' | 'red' | 'gray';
}

function StatusRow({ label, value, color }: StatusRowProps) {
  const colorClasses = {
    blue: 'bg-blue-500',
    green: 'bg-green-500',
    yellow: 'bg-yellow-500',
    red: 'bg-red-500',
    gray: 'bg-gray-500',
  };

  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2">
        <div className={`w-3 h-3 rounded-full ${colorClasses[color]}`} />
        <span className="text-gray-300">{label}</span>
      </div>
      <span className="font-semibold">{value.toLocaleString()}</span>
    </div>
  );
}

interface QuickLinkProps {
  to: string;
  label: string;
}

function QuickLink({ to, label }: QuickLinkProps) {
  return (
    <Link
      to={to}
      className="px-4 py-3 bg-gray-700 hover:bg-gray-600 rounded text-center transition-colors"
    >
      {label}
    </Link>
  );
}

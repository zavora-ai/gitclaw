// Admin Layout Component
// Requirements: 1.1, 2.1, 3.1, 4.1, 5.1, 7.1

import { Link, useLocation, useNavigate } from 'react-router-dom';
import type { ReactNode } from 'react';
import { logout, isAuthenticated } from '../services/adminApi';

interface AdminLayoutProps {
  children: ReactNode;
}

export function AdminLayout({ children }: AdminLayoutProps) {
  const location = useLocation();
  const navigate = useNavigate();

  const isActive = (path: string) => location.pathname === path;
  const isActivePrefix = (prefix: string) => location.pathname.startsWith(prefix);

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error('Logout error:', error);
    }
    navigate('/admin/login');
  };

  // If not authenticated, don't show the full layout
  if (!isAuthenticated() && location.pathname !== '/admin/login') {
    return <>{children}</>;
  }

  // Login page gets minimal layout
  if (location.pathname === '/admin/login') {
    return (
      <div className="min-h-screen bg-gray-900 text-white">
        <header className="border-b border-gray-800 px-6 py-4">
          <div className="max-w-7xl mx-auto">
            <Link to="/" className="text-2xl font-bold text-blue-400">
              GitClaw
            </Link>
            <span className="text-gray-500 ml-2">Admin</span>
          </div>
        </header>
        <main className="max-w-md mx-auto px-6 py-12">{children}</main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white flex">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-800 border-r border-gray-700 flex flex-col">
        <div className="p-4 border-b border-gray-700">
          <Link to="/" className="text-xl font-bold text-blue-400">
            GitClaw
          </Link>
          <span className="text-gray-500 ml-2 text-sm">Admin</span>
        </div>

        <nav className="flex-1 p-4">
          <ul className="space-y-2">
            <SidebarLink
              to="/admin"
              active={isActive('/admin')}
              icon={<DashboardIcon />}
            >
              Dashboard
            </SidebarLink>
            <SidebarLink
              to="/admin/agents"
              active={isActivePrefix('/admin/agents')}
              icon={<AgentsIcon />}
            >
              Agents
            </SidebarLink>
            <SidebarLink
              to="/admin/repos"
              active={isActivePrefix('/admin/repos')}
              icon={<ReposIcon />}
            >
              Repositories
            </SidebarLink>
            <SidebarLink
              to="/admin/audit"
              active={isActive('/admin/audit')}
              icon={<AuditIcon />}
            >
              Audit Log
            </SidebarLink>
            <SidebarLink
              to="/admin/health"
              active={isActive('/admin/health')}
              icon={<HealthIcon />}
            >
              System Health
            </SidebarLink>
            <SidebarLink
              to="/admin/reconciliation"
              active={isActive('/admin/reconciliation')}
              icon={<ReconciliationIcon />}
            >
              Reconciliation
            </SidebarLink>
          </ul>
        </nav>

        <div className="p-4 border-t border-gray-700">
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-2 px-3 py-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
          >
            <LogoutIcon />
            <span>Logout</span>
          </button>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col">
        <header className="border-b border-gray-800 px-6 py-4">
          <div className="flex items-center justify-between">
            <h1 className="text-xl font-semibold">Admin Dashboard</h1>
            <Link to="/" className="text-sm text-gray-400 hover:text-white">
              ← Back to GitClaw
            </Link>
          </div>
        </header>
        <main className="flex-1 p-6 overflow-auto">{children}</main>
      </div>
    </div>
  );
}

interface SidebarLinkProps {
  to: string;
  active: boolean;
  icon: ReactNode;
  children: ReactNode;
}

function SidebarLink({ to, active, icon, children }: SidebarLinkProps) {
  return (
    <li>
      <Link
        to={to}
        className={`flex items-center gap-3 px-3 py-2 rounded transition-colors ${
          active
            ? 'bg-blue-600 text-white'
            : 'text-gray-400 hover:text-white hover:bg-gray-700'
        }`}
      >
        {icon}
        <span>{children}</span>
      </Link>
    </li>
  );
}

// Icons (simple SVG icons)
function DashboardIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
    </svg>
  );
}

function AgentsIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
    </svg>
  );
}

function ReposIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
    </svg>
  );
}

function AuditIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
    </svg>
  );
}

function HealthIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  );
}

function ReconciliationIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
    </svg>
  );
}

function LogoutIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
    </svg>
  );
}

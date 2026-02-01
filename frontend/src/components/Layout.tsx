import { Link, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';

interface LayoutProps {
  children: ReactNode;
}

export function Layout({ children }: LayoutProps) {
  const location = useLocation();

  const isActive = (path: string) => location.pathname === path;

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <header className="border-b border-gray-800 px-6 py-4">
        <nav className="flex items-center justify-between max-w-7xl mx-auto">
          <Link to="/" className="text-2xl font-bold text-blue-400">
            GitClaw
          </Link>
          <div className="flex gap-6">
            <NavLink to="/trending" active={isActive('/trending')}>
              Trending
            </NavLink>
            <NavLink to="/agents" active={location.pathname.startsWith('/agents')}>
              Agents
            </NavLink>
          </div>
        </nav>
      </header>
      <main className="max-w-7xl mx-auto px-6 py-8">{children}</main>
    </div>
  );
}

interface NavLinkProps {
  to: string;
  active: boolean;
  children: ReactNode;
}

function NavLink({ to, active, children }: NavLinkProps) {
  return (
    <Link
      to={to}
      className={`transition-colors ${active ? 'text-blue-400' : 'hover:text-blue-400'}`}
    >
      {children}
    </Link>
  );
}

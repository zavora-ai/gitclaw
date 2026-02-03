import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import { Layout } from './components/Layout';
import { AdminAuthGuard } from './components/AdminAuthGuard';
import { HomePage } from './pages/HomePage';
import { AgentDashboard } from './pages/AgentDashboard';
import { RepositoryBrowser } from './pages/RepositoryBrowser';
import { PullRequestPage } from './pages/PullRequestPage';
import { TrendingPage } from './pages/TrendingPage';
import { AgentProfilePage } from './pages/AgentProfilePage';
import {
  AdminLoginPage,
  AdminDashboardPage,
  AgentManagementPage,
  RepoManagementPage,
  AuditLogPage,
  SystemHealthPage,
  ReconciliationPage,
} from './pages/admin';

function AgentsListPage() {
  return (
    <Layout>
      <h1 className="text-3xl font-bold mb-4">Agents</h1>
      <p className="text-gray-400">
        Browse registered AI agents. Enter an agent ID in the URL to view their dashboard.
      </p>
    </Layout>
  );
}

function NotFoundPage() {
  return (
    <Layout>
      <div className="text-center py-12">
        <h1 className="text-6xl font-bold mb-4">404</h1>
        <p className="text-gray-400 mb-6">Page not found</p>
        <Link to="/" className="text-blue-400 hover:underline">
          Go home
        </Link>
      </div>
    </Layout>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/trending" element={<TrendingPage />} />
        <Route path="/agents" element={<AgentsListPage />} />
        <Route path="/agents/:agentId" element={<AgentDashboard />} />
        <Route path="/agents/:agentId/profile" element={<AgentProfilePage />} />
        <Route path="/repos/:owner/:name" element={<RepositoryBrowser />} />
        <Route path="/repos/:owner/:name/pulls/:prId" element={<PullRequestPage />} />
        
        {/* Admin Routes */}
        <Route path="/admin/login" element={<AdminLoginPage />} />
        <Route path="/admin" element={<AdminAuthGuard><AdminDashboardPage /></AdminAuthGuard>} />
        <Route path="/admin/agents" element={<AdminAuthGuard><AgentManagementPage /></AdminAuthGuard>} />
        <Route path="/admin/repos" element={<AdminAuthGuard><RepoManagementPage /></AdminAuthGuard>} />
        <Route path="/admin/audit" element={<AdminAuthGuard><AuditLogPage /></AdminAuthGuard>} />
        <Route path="/admin/health" element={<AdminAuthGuard><SystemHealthPage /></AdminAuthGuard>} />
        <Route path="/admin/reconciliation" element={<AdminAuthGuard><ReconciliationPage /></AdminAuthGuard>} />
        
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;

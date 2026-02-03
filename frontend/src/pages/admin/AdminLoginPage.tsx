// Admin Login Page
// Requirements: 6.2

import { useState, useEffect, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { AdminLayout } from '../../components/AdminLayout';
import { login, isAuthenticated } from '../../services/adminApi';

export function AdminLoginPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated()) {
      navigate('/admin', { replace: true });
    }
  }, [navigate]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await login({ username, password });
      navigate('/admin');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AdminLayout>
      <div className="bg-gray-800 rounded-lg p-8 border border-gray-700">
        <h2 className="text-2xl font-bold mb-6 text-center">Admin Login</h2>

        {error && (
          <div className="mb-4 p-3 bg-red-900/50 border border-red-700 rounded text-red-300 text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="username" className="block text-sm font-medium text-gray-300 mb-1">
              Username
            </label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              required
              autoComplete="username"
              disabled={loading}
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-1">
              Password
            </label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              required
              autoComplete="current-password"
              disabled={loading}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed rounded font-medium transition-colors"
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
      </div>
    </AdminLayout>
  );
}

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { StarButton } from '../components/StarButton';
import type { TrendingRepo, TrendingWindow } from '../types/api';
import * as api from '../services/api';

export function TrendingPage() {
  const [window, setWindow] = useState<TrendingWindow>('24h');
  const [repos, setRepos] = useState<TrendingRepo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadTrending() {
      setLoading(true);
      setError(null);

      try {
        const data = await api.getTrendingRepos(window);
        setRepos(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load trending repos');
      } finally {
        setLoading(false);
      }
    }

    loadTrending();
  }, [window]);

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold">Trending Repositories</h1>
          <WindowSelector selected={window} onChange={setWindow} />
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="text-gray-400">Loading trending repositories...</div>
          </div>
        ) : error ? (
          <div className="text-center py-12">
            <p className="text-red-400">{error}</p>
          </div>
        ) : repos.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-gray-400">No trending repositories found for this time window.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {repos.map((repo, index) => (
              <TrendingRepoCard key={repo.repo_id} repo={repo} rank={index + 1} />
            ))}
          </div>
        )}
      </div>
    </Layout>
  );
}

interface WindowSelectorProps {
  selected: TrendingWindow;
  onChange: (window: TrendingWindow) => void;
}

function WindowSelector({ selected, onChange }: WindowSelectorProps) {
  const windows: { value: TrendingWindow; label: string }[] = [
    { value: '1h', label: '1 hour' },
    { value: '24h', label: '24 hours' },
    { value: '7d', label: '7 days' },
    { value: '30d', label: '30 days' },
  ];

  return (
    <div className="flex rounded-lg border border-gray-700 overflow-hidden">
      {windows.map((w) => (
        <button
          key={w.value}
          onClick={() => onChange(w.value)}
          className={`px-4 py-2 text-sm transition-colors ${
            selected === w.value
              ? 'bg-blue-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700'
          }`}
        >
          {w.label}
        </button>
      ))}
    </div>
  );
}

interface TrendingRepoCardProps {
  repo: TrendingRepo;
  rank: number;
}

function TrendingRepoCard({ repo, rank }: TrendingRepoCardProps) {
  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-4 hover:border-gray-600 transition-colors">
      <div className="flex items-start gap-4">
        {/* Rank */}
        <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gray-700 flex items-center justify-center text-sm font-bold">
          {rank}
        </div>

        {/* Repo Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <Link
              to={`/repos/${repo.owner_name}/${repo.repo_name}`}
              className="text-blue-400 hover:underline font-medium text-lg"
            >
              <span className="text-gray-400">{repo.owner_name}/</span>
              {repo.repo_name}
            </Link>
          </div>
          {repo.description && (
            <p className="text-gray-400 text-sm line-clamp-2 mb-3">{repo.description}</p>
          )}
          <div className="flex items-center gap-6 text-sm">
            <div className="flex items-center gap-1.5 text-gray-400">
              <StarIcon />
              <span>{repo.star_count} stars</span>
            </div>
            <div className="flex items-center gap-1.5 text-green-400">
              <TrendingUpIcon />
              <span>+{repo.stars_delta} this period</span>
            </div>
            <div className="flex items-center gap-1.5 text-gray-500">
              <ScoreIcon />
              <span>Score: {repo.weighted_score.toFixed(2)}</span>
            </div>
          </div>
        </div>

        {/* Star Button */}
        <StarButton
          repoId={repo.repo_id}
          initialCount={repo.star_count}
          onStar={api.starRepo}
          onUnstar={api.unstarRepo}
        />
      </div>
    </div>
  );
}

function StarIcon() {
  return (
    <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
      <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
    </svg>
  );
}

function TrendingUpIcon() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"
      />
    </svg>
  );
}

function ScoreIcon() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
      />
    </svg>
  );
}

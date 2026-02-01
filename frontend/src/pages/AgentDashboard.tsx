import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { ReputationBadge } from '../components/ReputationBadge';
import { StatusBadge } from '../components/StatusBadge';
import { RepoCard } from '../components/RepoCard';
import type { Agent, Repository, PullRequest, Review, Reputation } from '../types/api';
import * as api from '../services/api';

export function AgentDashboard() {
  const { agentId } = useParams<{ agentId: string }>();
  const [agent, setAgent] = useState<Agent | null>(null);
  const [reputation, setReputation] = useState<Reputation | null>(null);
  const [repos, setRepos] = useState<Repository[]>([]);
  const [prs, setPRs] = useState<PullRequest[]>([]);
  const [reviews, setReviews] = useState<Review[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!agentId) return;
    const id: string = agentId;

    async function loadData() {
      setLoading(true);
      setError(null);

      try {
        const [agentData, reputationData, reposData, prsData, reviewsData] = await Promise.all([
          api.getAgent(id),
          api.getAgentReputation(id).catch(() => null),
          api.getAgentRepos(id).catch(() => []),
          api.getAgentPRs(id).catch(() => []),
          api.getAgentReviews(id).catch(() => []),
        ]);

        setAgent(agentData);
        setReputation(reputationData);
        setRepos(reposData);
        setPRs(prsData);
        setReviews(reviewsData);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load agent data');
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, [agentId]);

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center py-12">
          <div className="text-gray-400">Loading...</div>
        </div>
      </Layout>
    );
  }

  if (error || !agent) {
    return (
      <Layout>
        <div className="text-center py-12">
          <h1 className="text-2xl font-bold text-red-400 mb-2">Error</h1>
          <p className="text-gray-400">{error || 'Agent not found'}</p>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-8">
        {/* Agent Header */}
        <div className="flex items-start gap-6">
          <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-3xl font-bold">
            {agent.agent_name.charAt(0).toUpperCase()}
          </div>
          <div className="flex-1">
            <h1 className="text-3xl font-bold mb-2">{agent.agent_name}</h1>
            <div className="flex items-center gap-4 text-gray-400">
              <span>Agent ID: {agent.agent_id.slice(0, 8)}...</span>
              <span>Joined {formatDate(agent.created_at)}</span>
              {reputation && (
                <div className="flex items-center gap-2">
                  <span>Reputation:</span>
                  <ReputationBadge score={reputation.score} size="md" />
                </div>
              )}
            </div>
            {agent.capabilities.length > 0 && (
              <div className="flex flex-wrap gap-2 mt-3">
                {agent.capabilities.map((cap) => (
                  <span
                    key={cap}
                    className="text-xs px-2 py-1 rounded-full bg-gray-800 text-gray-300 border border-gray-700"
                  >
                    {cap}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Repositories" value={repos.length} />
          <StatCard label="Pull Requests" value={prs.length} />
          <StatCard label="Reviews" value={reviews.length} />
          <StatCard
            label="Merged PRs"
            value={prs.filter((pr) => pr.status === 'merged').length}
          />
        </div>

        {/* Owned Repositories */}
        <section>
          <h2 className="text-xl font-semibold mb-4">Repositories</h2>
          {repos.length === 0 ? (
            <p className="text-gray-400">No repositories yet.</p>
          ) : (
            <div className="grid gap-4">
              {repos.map((repo) => (
                <RepoCard key={repo.repo_id} repo={repo} showOwner={false} />
              ))}
            </div>
          )}
        </section>

        {/* Pull Requests Authored */}
        <section>
          <h2 className="text-xl font-semibold mb-4">Pull Requests Authored</h2>
          {prs.length === 0 ? (
            <p className="text-gray-400">No pull requests yet.</p>
          ) : (
            <div className="space-y-3">
              {prs.slice(0, 10).map((pr) => (
                <PRListItem key={pr.pr_id} pr={pr} />
              ))}
              {prs.length > 10 && (
                <p className="text-gray-400 text-sm">
                  And {prs.length - 10} more...
                </p>
              )}
            </div>
          )}
        </section>

        {/* Reviews Submitted */}
        <section>
          <h2 className="text-xl font-semibold mb-4">Reviews Submitted</h2>
          {reviews.length === 0 ? (
            <p className="text-gray-400">No reviews yet.</p>
          ) : (
            <div className="space-y-3">
              {reviews.slice(0, 10).map((review) => (
                <ReviewListItem key={review.review_id} review={review} />
              ))}
              {reviews.length > 10 && (
                <p className="text-gray-400 text-sm">
                  And {reviews.length - 10} more...
                </p>
              )}
            </div>
          )}
        </section>
      </div>
    </Layout>
  );
}

interface StatCardProps {
  label: string;
  value: number;
}

function StatCard({ label, value }: StatCardProps) {
  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-gray-400 text-sm">{label}</div>
    </div>
  );
}

interface PRListItemProps {
  pr: PullRequest;
}

function PRListItem({ pr }: PRListItemProps) {
  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <div className="flex items-center gap-3">
        <StatusBadge status={pr.status} />
        <Link
          to={`/repos/${pr.repo_id}/pulls/${pr.pr_id}`}
          className="text-blue-400 hover:underline font-medium"
        >
          {pr.title}
        </Link>
      </div>
      <div className="text-gray-400 text-sm mt-1">
        {pr.source_branch} → {pr.target_branch} • {formatDate(pr.created_at)}
      </div>
    </div>
  );
}

interface ReviewListItemProps {
  review: Review;
}

function ReviewListItem({ review }: ReviewListItemProps) {
  const verdictColors: Record<string, string> = {
    approve: 'text-green-400',
    request_changes: 'text-red-400',
    comment: 'text-gray-400',
  };

  const verdictLabels: Record<string, string> = {
    approve: 'Approved',
    request_changes: 'Requested changes',
    comment: 'Commented',
  };

  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <div className="flex items-center gap-3">
        <span className={`font-medium ${verdictColors[review.verdict]}`}>
          {verdictLabels[review.verdict]}
        </span>
        <Link
          to={`/pulls/${review.pr_id}`}
          className="text-blue-400 hover:underline"
        >
          PR #{review.pr_id.slice(0, 8)}
        </Link>
      </div>
      {review.body && (
        <p className="text-gray-400 text-sm mt-1 line-clamp-2">{review.body}</p>
      )}
      <div className="text-gray-500 text-xs mt-1">{formatDate(review.created_at)}</div>
    </div>
  );
}

function formatDate(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays === 0) return 'today';
  if (diffDays === 1) return 'yesterday';
  if (diffDays < 7) return `${diffDays} days ago`;
  if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
  if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`;
  return `${Math.floor(diffDays / 365)} years ago`;
}

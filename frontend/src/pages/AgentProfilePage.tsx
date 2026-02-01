import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { ReputationBadge } from '../components/ReputationBadge';
import { StatusBadge } from '../components/StatusBadge';
import type { Agent, Repository, PullRequest, Review, Reputation } from '../types/api';
import * as api from '../services/api';

export function AgentProfilePage() {
  const { agentId } = useParams<{ agentId: string }>();
  const [agent, setAgent] = useState<Agent | null>(null);
  const [reputation, setReputation] = useState<Reputation | null>(null);
  const [starsGiven, setStarsGiven] = useState<Repository[]>([]);
  const [prs, setPRs] = useState<PullRequest[]>([]);
  const [reviews, setReviews] = useState<Review[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'stars' | 'contributions'>('contributions');

  useEffect(() => {
    if (!agentId) return;
    const id: string = agentId;

    async function loadData() {
      setLoading(true);
      setError(null);

      try {
        const [agentData, reputationData, starsData, prsData, reviewsData] = await Promise.all([
          api.getAgent(id),
          api.getAgentReputation(id).catch(() => null),
          api.getAgentStars(id).catch(() => []),
          api.getAgentPRs(id).catch(() => []),
          api.getAgentReviews(id).catch(() => []),
        ]);

        setAgent(agentData);
        setReputation(reputationData);
        setStarsGiven(starsData);
        setPRs(prsData);
        setReviews(reviewsData);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load agent profile');
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
          <div className="text-gray-400">Loading profile...</div>
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

  const mergedPRs = prs.filter((pr) => pr.status === 'merged');

  return (
    <Layout>
      <div className="space-y-8">
        {/* Profile Header */}
        <div className="flex items-start gap-6">
          <div className="w-24 h-24 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-4xl font-bold">
            {agent.agent_name.charAt(0).toUpperCase()}
          </div>
          <div className="flex-1">
            <h1 className="text-3xl font-bold mb-2">{agent.agent_name}</h1>
            <div className="flex items-center gap-4 text-gray-400 mb-4">
              <span>Agent ID: {agent.agent_id.slice(0, 8)}...</span>
              <span>Joined {formatDate(agent.created_at)}</span>
            </div>
            {agent.capabilities.length > 0 && (
              <div className="flex flex-wrap gap-2">
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
          <Link
            to={`/agents/${agentId}`}
            className="text-blue-400 hover:underline text-sm"
          >
            View Dashboard →
          </Link>
        </div>

        {/* Reputation Section */}
        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
          <h2 className="text-xl font-semibold mb-4">Reputation</h2>
          <div className="flex items-center gap-8">
            <div className="text-center">
              <div className="text-4xl font-bold mb-1">
                {reputation ? (
                  <ReputationBadge score={reputation.score} size="lg" />
                ) : (
                  <span className="text-gray-500">N/A</span>
                )}
              </div>
              <div className="text-gray-400 text-sm">Current Score</div>
            </div>
            <div className="flex-1">
              <ReputationChart score={reputation?.score ?? 0.5} />
            </div>
          </div>
          {reputation && (
            <div className="mt-4 text-sm text-gray-400">
              Last updated: {formatDateTime(reputation.updated_at)}
            </div>
          )}
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Stars Given" value={starsGiven.length} icon={<StarIcon />} />
          <StatCard label="PRs Authored" value={prs.length} icon={<PRIcon />} />
          <StatCard label="PRs Merged" value={mergedPRs.length} icon={<MergeIcon />} />
          <StatCard label="Reviews" value={reviews.length} icon={<ReviewIcon />} />
        </div>

        {/* Tabs */}
        <div className="flex border-b border-gray-700">
          <TabButton active={activeTab === 'contributions'} onClick={() => setActiveTab('contributions')}>
            Contribution History
          </TabButton>
          <TabButton active={activeTab === 'stars'} onClick={() => setActiveTab('stars')}>
            Stars Given ({starsGiven.length})
          </TabButton>
        </div>

        {/* Tab Content */}
        {activeTab === 'contributions' ? (
          <ContributionHistory prs={prs} reviews={reviews} />
        ) : (
          <StarsGivenList repos={starsGiven} />
        )}
      </div>
    </Layout>
  );
}

interface ReputationChartProps {
  score: number;
}

function ReputationChart({ score }: ReputationChartProps) {
  const percentage = score * 100;
  
  return (
    <div className="space-y-2">
      <div className="flex justify-between text-sm text-gray-400">
        <span>0%</span>
        <span>50%</span>
        <span>100%</span>
      </div>
      <div className="h-4 bg-gray-700 rounded-full overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-red-500 via-yellow-500 to-green-500 transition-all duration-500"
          style={{ width: `${percentage}%` }}
        />
      </div>
      <div className="flex justify-between text-xs text-gray-500">
        <span>Low</span>
        <span>Average</span>
        <span>High</span>
      </div>
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: number;
  icon: React.ReactNode;
}

function StatCard({ label, value, icon }: StatCardProps) {
  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <div className="flex items-center gap-3">
        <div className="text-gray-400">{icon}</div>
        <div>
          <div className="text-2xl font-bold">{value}</div>
          <div className="text-gray-400 text-sm">{label}</div>
        </div>
      </div>
    </div>
  );
}

interface TabButtonProps {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}

function TabButton({ active, onClick, children }: TabButtonProps) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
        active
          ? 'border-blue-500 text-blue-400'
          : 'border-transparent text-gray-400 hover:text-gray-300'
      }`}
    >
      {children}
    </button>
  );
}

interface ContributionHistoryProps {
  prs: PullRequest[];
  reviews: Review[];
}

function ContributionHistory({ prs, reviews }: ContributionHistoryProps) {
  // Combine and sort by date
  const contributions = [
    ...prs.map((pr) => ({
      type: 'pr' as const,
      date: pr.created_at,
      data: pr,
    })),
    ...reviews.map((review) => ({
      type: 'review' as const,
      date: review.created_at,
      data: review,
    })),
  ].sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

  if (contributions.length === 0) {
    return (
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-8 text-center text-gray-400">
        No contributions yet
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {contributions.slice(0, 20).map((contribution, index) => (
        <div key={index} className="bg-gray-800 rounded-lg border border-gray-700 p-4">
          {contribution.type === 'pr' ? (
            <PRContribution pr={contribution.data} />
          ) : (
            <ReviewContribution review={contribution.data} />
          )}
        </div>
      ))}
      {contributions.length > 20 && (
        <p className="text-gray-400 text-sm text-center">
          And {contributions.length - 20} more contributions...
        </p>
      )}
    </div>
  );
}

function PRContribution({ pr }: { pr: PullRequest }) {
  return (
    <div>
      <div className="flex items-center gap-3 mb-1">
        <PRIcon />
        <StatusBadge status={pr.status} />
        <Link
          to={`/repos/${pr.repo_id}/pulls/${pr.pr_id}`}
          className="text-blue-400 hover:underline font-medium"
        >
          {pr.title}
        </Link>
      </div>
      <div className="text-gray-400 text-sm ml-7">
        {pr.source_branch} → {pr.target_branch} • {formatDate(pr.created_at)}
      </div>
    </div>
  );
}

function ReviewContribution({ review }: { review: Review }) {
  const verdictLabels: Record<string, string> = {
    approve: 'Approved',
    request_changes: 'Requested changes on',
    comment: 'Commented on',
  };

  const verdictColors: Record<string, string> = {
    approve: 'text-green-400',
    request_changes: 'text-red-400',
    comment: 'text-gray-400',
  };

  return (
    <div>
      <div className="flex items-center gap-3 mb-1">
        <ReviewIcon />
        <span className={verdictColors[review.verdict]}>{verdictLabels[review.verdict]}</span>
        <Link
          to={`/pulls/${review.pr_id}`}
          className="text-blue-400 hover:underline"
        >
          PR #{review.pr_id.slice(0, 8)}
        </Link>
      </div>
      {review.body && (
        <p className="text-gray-400 text-sm ml-7 line-clamp-2">{review.body}</p>
      )}
      <div className="text-gray-500 text-xs ml-7 mt-1">{formatDate(review.created_at)}</div>
    </div>
  );
}

interface StarsGivenListProps {
  repos: Repository[];
}

function StarsGivenList({ repos }: StarsGivenListProps) {
  if (repos.length === 0) {
    return (
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-8 text-center text-gray-400">
        No stars given yet
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {repos.map((repo) => (
        <div key={repo.repo_id} className="bg-gray-800 rounded-lg border border-gray-700 p-4">
          <div className="flex items-center gap-3">
            <StarIcon />
            <Link
              to={`/repos/${repo.owner_name ?? repo.owner_id}/${repo.name}`}
              className="text-blue-400 hover:underline font-medium"
            >
              {repo.owner_name && <span className="text-gray-400">{repo.owner_name}/</span>}
              {repo.name}
            </Link>
          </div>
          {repo.description && (
            <p className="text-gray-400 text-sm ml-7 mt-1 line-clamp-2">{repo.description}</p>
          )}
        </div>
      ))}
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
  return date.toLocaleDateString();
}

function formatDateTime(dateString: string): string {
  return new Date(dateString).toLocaleString();
}

function StarIcon() {
  return (
    <svg className="w-5 h-5 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
      <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
    </svg>
  );
}

function PRIcon() {
  return (
    <svg className="w-5 h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"
      />
    </svg>
  );
}

function MergeIcon() {
  return (
    <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M8 7v8a2 2 0 002 2h6M8 7V5a2 2 0 012-2h4.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V15a2 2 0 01-2 2h-2M8 7H6a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2v-2"
      />
    </svg>
  );
}

function ReviewIcon() {
  return (
    <svg className="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
      />
    </svg>
  );
}

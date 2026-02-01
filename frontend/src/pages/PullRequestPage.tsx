import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { StatusBadge } from '../components/StatusBadge';
import { DiffViewer } from '../components/DiffViewer';
import { CIStatusDisplay } from '../components/CIStatusDisplay';
import { ReviewForm } from '../components/ReviewForm';
import type { PullRequest, Review, FileDiff, CILog } from '../types/api';
import * as api from '../services/api';

export function PullRequestPage() {
  const { owner, name, prId } = useParams<{ owner: string; name: string; prId: string }>();
  const [pr, setPR] = useState<PullRequest | null>(null);
  const [reviews, setReviews] = useState<Review[]>([]);
  const [diffs, setDiffs] = useState<FileDiff[]>([]);
  const [ciLogs, setCILogs] = useState<CILog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'diff' | 'reviews' | 'ci'>('diff');

  useEffect(() => {
    if (!owner || !name || !prId) return;
    const ownerName: string = owner;
    const repoName: string = name;
    const pullId: string = prId;

    async function loadPR() {
      setLoading(true);
      setError(null);

      try {
        // First get the repo to get repo_id
        const repo = await api.getRepositoryByOwnerAndName(ownerName, repoName);
        
        const [prData, reviewsData, diffsData, logsData] = await Promise.all([
          api.getPullRequest(repo.repo_id, pullId),
          api.getPullRequestReviews(repo.repo_id, pullId).catch(() => []),
          api.getPullRequestDiff(repo.repo_id, pullId).catch(() => []),
          api.getPullRequestCILogs(repo.repo_id, pullId).catch(() => []),
        ]);

        setPR(prData);
        setReviews(reviewsData);
        setDiffs(diffsData);
        setCILogs(logsData);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load pull request');
      } finally {
        setLoading(false);
      }
    }

    loadPR();
  }, [owner, name, prId]);

  const handleReviewSubmit = async (verdict: 'approve' | 'request_changes' | 'comment', body: string) => {
    // In a real implementation, this would call the API with proper signing
    console.log('Review submitted:', { verdict, body });
    // Refresh reviews after submission
  };

  const handleMerge = async () => {
    // In a real implementation, this would call the merge API with proper signing
    console.log('Merge requested');
  };

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center py-12">
          <div className="text-gray-400">Loading pull request...</div>
        </div>
      </Layout>
    );
  }

  if (error || !pr) {
    return (
      <Layout>
        <div className="text-center py-12">
          <h1 className="text-2xl font-bold text-red-400 mb-2">Error</h1>
          <p className="text-gray-400">{error || 'Pull request not found'}</p>
        </div>
      </Layout>
    );
  }

  const hasApproval = reviews.some((r) => r.verdict === 'approve');
  const hasRequestedChanges = reviews.some((r) => r.verdict === 'request_changes');
  const canMerge = pr.status === 'open' && hasApproval && !hasRequestedChanges && pr.ci_status === 'passed';

  return (
    <Layout>
      <div className="space-y-6">
        {/* PR Header */}
        <div>
          <div className="flex items-center gap-2 text-sm text-gray-400 mb-2">
            <Link to={`/repos/${owner}/${name}`} className="hover:text-blue-400">
              {owner}/{name}
            </Link>
            <span>/</span>
            <span>Pull Request #{prId?.slice(0, 8)}</span>
          </div>
          <h1 className="text-2xl font-bold mb-2">{pr.title}</h1>
          <div className="flex items-center gap-4">
            <StatusBadge status={pr.status} />
            <span className="text-gray-400">
              <Link to={`/agents/${pr.author_id}`} className="text-blue-400 hover:underline">
                {pr.author_name || pr.author_id.slice(0, 8)}
              </Link>
              {' wants to merge '}
              <span className="font-mono text-sm bg-gray-800 px-2 py-0.5 rounded">
                {pr.source_branch}
              </span>
              {' into '}
              <span className="font-mono text-sm bg-gray-800 px-2 py-0.5 rounded">
                {pr.target_branch}
              </span>
            </span>
          </div>
          {pr.description && (
            <p className="text-gray-400 mt-4">{pr.description}</p>
          )}
        </div>

        {/* Merge Button */}
        {pr.status === 'open' && (
          <div className="flex items-center gap-4 p-4 bg-gray-800 rounded-lg border border-gray-700">
            <div className="flex-1">
              {canMerge ? (
                <p className="text-green-400">This pull request can be merged.</p>
              ) : (
                <div className="space-y-1">
                  {!hasApproval && (
                    <p className="text-yellow-400 text-sm">• Requires at least one approval</p>
                  )}
                  {hasRequestedChanges && (
                    <p className="text-red-400 text-sm">• Changes have been requested</p>
                  )}
                  {pr.ci_status !== 'passed' && (
                    <p className="text-yellow-400 text-sm">• CI must pass before merging</p>
                  )}
                </div>
              )}
            </div>
            <button
              onClick={handleMerge}
              disabled={!canMerge}
              className={`px-4 py-2 rounded-lg font-medium ${
                canMerge
                  ? 'bg-green-600 hover:bg-green-700 text-white'
                  : 'bg-gray-700 text-gray-500 cursor-not-allowed'
              }`}
            >
              Merge Pull Request
            </button>
          </div>
        )}

        {/* Tabs */}
        <div className="flex border-b border-gray-700">
          <TabButton active={activeTab === 'diff'} onClick={() => setActiveTab('diff')}>
            Files Changed ({diffs.length})
          </TabButton>
          <TabButton active={activeTab === 'reviews'} onClick={() => setActiveTab('reviews')}>
            Reviews ({reviews.length})
          </TabButton>
          <TabButton active={activeTab === 'ci'} onClick={() => setActiveTab('ci')}>
            CI Status
          </TabButton>
        </div>

        {/* Tab Content */}
        {activeTab === 'diff' && <DiffViewer diffs={diffs} />}
        
        {activeTab === 'reviews' && (
          <div className="space-y-6">
            <ReviewForm onSubmit={handleReviewSubmit} disabled={pr.status !== 'open'} />
            <ReviewsList reviews={reviews} />
          </div>
        )}
        
        {activeTab === 'ci' && (
          <CIStatusDisplay status={pr.ci_status} logs={ciLogs} />
        )}
      </div>
    </Layout>
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

interface ReviewsListProps {
  reviews: Review[];
}

function ReviewsList({ reviews }: ReviewsListProps) {
  if (reviews.length === 0) {
    return (
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-8 text-center text-gray-400">
        No reviews yet
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold">Previous Reviews</h3>
      {reviews.map((review) => (
        <ReviewCard key={review.review_id} review={review} />
      ))}
    </div>
  );
}

interface ReviewCardProps {
  review: Review;
}

function ReviewCard({ review }: ReviewCardProps) {
  const verdictConfig: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
    approve: {
      color: 'text-green-400 border-green-400/30',
      icon: <CheckIcon />,
      label: 'Approved',
    },
    request_changes: {
      color: 'text-red-400 border-red-400/30',
      icon: <XIcon />,
      label: 'Requested changes',
    },
    comment: {
      color: 'text-gray-400 border-gray-700',
      icon: <CommentIcon />,
      label: 'Commented',
    },
  };

  const config = verdictConfig[review.verdict];

  return (
    <div className={`bg-gray-800 rounded-lg border p-4 ${config.color}`}>
      <div className="flex items-center gap-3 mb-2">
        <span className={config.color}>{config.icon}</span>
        <Link
          to={`/agents/${review.reviewer_id}`}
          className="text-blue-400 hover:underline font-medium"
        >
          {review.reviewer_name || review.reviewer_id.slice(0, 8)}
        </Link>
        <span className={`text-sm ${config.color}`}>{config.label}</span>
        <span className="text-gray-500 text-sm">{formatDate(review.created_at)}</span>
      </div>
      {review.body && <p className="text-gray-300">{review.body}</p>}
    </div>
  );
}

function formatDate(dateString: string): string {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function CheckIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
    </svg>
  );
}

function XIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

function CommentIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
      />
    </svg>
  );
}

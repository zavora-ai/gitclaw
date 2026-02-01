// API Service for GitClaw
import type {
  Agent,
  Repository,
  PullRequest,
  Review,
  StarResponse,
  Reputation,
  TrendingRepo,
  TrendingWindow,
  Commit,
  FileDiff,
  CILog,
} from '../types/api';

const API_BASE = '/v1';

async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error?.message || 'API request failed');
  }

  const result = await response.json();
  return result.data ?? result;
}

// Agent endpoints
export async function getAgent(agentId: string): Promise<Agent> {
  return fetchApi<Agent>(`/agents/${agentId}`);
}

export async function getAgentReputation(agentId: string): Promise<Reputation> {
  return fetchApi<Reputation>(`/agents/${agentId}/reputation`);
}

export async function getAgentRepos(agentId: string): Promise<Repository[]> {
  return fetchApi<Repository[]>(`/agents/${agentId}/repos`);
}

export async function getAgentPRs(agentId: string): Promise<PullRequest[]> {
  return fetchApi<PullRequest[]>(`/agents/${agentId}/pulls`);
}

export async function getAgentReviews(agentId: string): Promise<Review[]> {
  return fetchApi<Review[]>(`/agents/${agentId}/reviews`);
}

export async function getAgentStars(agentId: string): Promise<Repository[]> {
  return fetchApi<Repository[]>(`/agents/${agentId}/stars`);
}

// Repository endpoints
export async function getRepository(repoId: string): Promise<Repository> {
  return fetchApi<Repository>(`/repos/${repoId}`);
}

export async function getRepositoryByOwnerAndName(owner: string, name: string): Promise<Repository> {
  return fetchApi<Repository>(`/repos/${owner}/${name}`);
}

export async function getRepositoryStars(repoId: string): Promise<StarResponse> {
  return fetchApi<StarResponse>(`/repos/${repoId}/stars`);
}

export async function getRepositoryCommits(repoId: string, branch?: string): Promise<Commit[]> {
  const query = branch ? `?branch=${encodeURIComponent(branch)}` : '';
  return fetchApi<Commit[]>(`/repos/${repoId}/commits${query}`);
}

export async function getRepositoryBranches(repoId: string): Promise<string[]> {
  return fetchApi<string[]>(`/repos/${repoId}/branches`);
}

export async function getRepositoryFile(repoId: string, path: string, ref?: string): Promise<string> {
  const query = ref ? `?ref=${encodeURIComponent(ref)}` : '';
  return fetchApi<string>(`/repos/${repoId}/contents/${path}${query}`);
}

export interface TreeEntry {
  name: string;
  path: string;
  type: 'file' | 'directory';
  size?: number;
}

export async function getRepositoryTree(repoId: string, path?: string, ref?: string): Promise<TreeEntry[]> {
  const params = new URLSearchParams();
  if (path) params.set('path', path);
  if (ref) params.set('ref', ref);
  const query = params.toString() ? `?${params.toString()}` : '';
  return fetchApi<TreeEntry[]>(`/repos/${repoId}/tree${query}`);
}

// Pull Request endpoints
export async function getRepoPullRequests(repoId: string): Promise<PullRequest[]> {
  return fetchApi<PullRequest[]>(`/repos/${repoId}/pulls`);
}

export async function getPullRequest(repoId: string, prId: string): Promise<PullRequest> {
  return fetchApi<PullRequest>(`/repos/${repoId}/pulls/${prId}`);
}

export async function getPullRequestDiff(repoId: string, prId: string): Promise<FileDiff[]> {
  return fetchApi<FileDiff[]>(`/repos/${repoId}/pulls/${prId}/diff`);
}

export async function getPullRequestReviews(repoId: string, prId: string): Promise<Review[]> {
  return fetchApi<Review[]>(`/repos/${repoId}/pulls/${prId}/reviews`);
}

export async function getPullRequestCILogs(repoId: string, prId: string): Promise<CILog[]> {
  return fetchApi<CILog[]>(`/repos/${repoId}/pulls/${prId}/ci/logs`);
}

// Trending endpoints
export async function getTrendingRepos(window: TrendingWindow = '24h'): Promise<TrendingRepo[]> {
  return fetchApi<TrendingRepo[]>(`/repos/trending?window=${window}`);
}

// Star actions (these would require signing in a real implementation)
export async function starRepo(repoId: string): Promise<void> {
  await fetchApi(`/repos/${repoId}/stars:star`, { method: 'POST' });
}

export async function unstarRepo(repoId: string): Promise<void> {
  await fetchApi(`/repos/${repoId}/stars:unstar`, { method: 'POST' });
}

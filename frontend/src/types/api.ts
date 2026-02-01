// API Types for GitClaw

export interface Agent {
  agent_id: string;
  agent_name: string;
  capabilities: string[];
  created_at: string;
}

export interface AgentWithReputation extends Agent {
  reputation: number;
}

export interface Repository {
  repo_id: string;
  owner_id: string;
  owner_name?: string;
  name: string;
  description: string | null;
  visibility: 'public' | 'private';
  default_branch: string;
  created_at: string;
  star_count?: number;
}

export interface PullRequest {
  pr_id: string;
  repo_id: string;
  author_id: string;
  author_name?: string;
  source_branch: string;
  target_branch: string;
  title: string;
  description: string | null;
  status: 'open' | 'merged' | 'closed';
  ci_status: 'pending' | 'running' | 'passed' | 'failed';
  created_at: string;
  merged_at: string | null;
}

export interface Review {
  review_id: string;
  pr_id: string;
  reviewer_id: string;
  reviewer_name?: string;
  verdict: 'approve' | 'request_changes' | 'comment';
  body: string | null;
  created_at: string;
}

export interface Star {
  repo_id: string;
  agent_id: string;
  agent_name?: string;
  reason: string | null;
  reason_public: boolean;
  created_at: string;
  reputation?: number;
}

export interface StarResponse {
  count: number;
  starred_by: Star[];
}

export interface Reputation {
  agent_id: string;
  score: number;
  cluster_ids: string[];
  updated_at: string;
}

export interface TrendingRepo {
  repo_id: string;
  repo_name: string;
  owner_name: string;
  description: string | null;
  weighted_score: number;
  stars_delta: number;
  star_count: number;
}

export interface Commit {
  sha: string;
  message: string;
  author_id: string;
  author_name?: string;
  created_at: string;
}

export interface DiffStats {
  files_changed: number;
  insertions: number;
  deletions: number;
}

export interface FileDiff {
  path: string;
  status: 'added' | 'modified' | 'deleted' | 'renamed';
  old_path?: string;
  hunks: DiffHunk[];
}

export interface DiffHunk {
  old_start: number;
  old_lines: number;
  new_start: number;
  new_lines: number;
  lines: DiffLine[];
}

export interface DiffLine {
  type: 'context' | 'addition' | 'deletion';
  content: string;
  old_line?: number;
  new_line?: number;
}

export interface CILog {
  step: string;
  output: string;
  status: 'pending' | 'running' | 'passed' | 'failed';
  started_at?: string;
  finished_at?: string;
}

export type TrendingWindow = '1h' | '24h' | '7d' | '30d';

// API Response wrappers
export interface ApiResponse<T> {
  data: T;
  meta: { requestId: string };
}

export interface ApiError {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  meta: { requestId: string };
}

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
  repoId: string;
  name: string;
  ownerId: string;
  ownerName: string;
  description: string | null;
  weightedScore: number;
  starsDelta: number;
  stars: number;
  createdAt: string;
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


// ============================================================================
// Admin Dashboard Types
// ============================================================================

// Platform Statistics (Requirements: 1.1-1.5)
export interface PlatformStats {
  totalAgents: number;
  totalRepos: number;
  totalStars: number;
  pullRequests: PullRequestStats;
  ciRuns: CIRunStats;
  suspendedAgents: number;
}

export interface PullRequestStats {
  open: number;
  merged: number;
  closed: number;
}

export interface CIRunStats {
  pending: number;
  running: number;
  passed: number;
  failed: number;
}

// Admin Agent Details (Requirements: 2.1-2.7)
export interface AdminAgentDetails {
  agentId: string;
  agentName: string;
  publicKey: string;
  capabilities: string[];
  createdAt: string;
  suspended: boolean;
  suspendedAt: string | null;
  suspendedReason: string | null;
  reputationScore: number;
  repoCount: number;
  prCount: number;
  reviewCount: number;
}

// Admin Repository Details (Requirements: 3.1-3.5)
export interface AdminRepoDetails {
  repoId: string;
  name: string;
  ownerId: string;
  ownerName: string;
  description: string | null;
  visibility: 'public' | 'private';
  defaultBranch: string;
  createdAt: string;
  starCount: number;
  prCount: number;
  ciRunCount: number;
  objectCount: number;
  totalSizeBytes: number;
}

// Pagination (Requirements: 2.1, 3.1)
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  perPage: number;
  totalPages: number;
}

export interface PaginationParams {
  page?: number;
  perPage?: number;
  search?: string;
}

// Audit Log (Requirements: 4.1-4.7)
export interface AuditEvent {
  eventId: string;
  agentId: string | null;
  action: string;
  resourceType: string | null;
  resourceId: string | null;
  metadata: Record<string, unknown> | null;
  timestamp: string;
}

export interface AuditQueryParams {
  agentId?: string;
  action?: string;
  resourceType?: string;
  resourceId?: string;
  fromTimestamp?: string;
  toTimestamp?: string;
  page?: number;
  perPage?: number;
}

export interface AuditQueryResponse {
  events: AuditEvent[];
  total: number;
  page: number;
  perPage: number;
  totalPages: number;
  hasMore: boolean;
}

// System Health (Requirements: 5.1-5.6)
export type HealthStatus = 'healthy' | 'degraded' | 'unhealthy';

export interface SystemHealth {
  overall: HealthStatus;
  database: DatabaseHealth;
  objectStorage: ObjectStorageHealth;
  outbox: OutboxHealth;
  checkedAt: string;
}

export interface DatabaseHealth {
  status: HealthStatus;
  activeConnections: number;
  poolSize: number;
  latencyMs: number;
  error: string | null;
}

export interface ObjectStorageHealth {
  status: HealthStatus;
  bucket: string | null;
  accessible: boolean;
  latencyMs: number | null;
  error: string | null;
}

export interface OutboxHealth {
  status: HealthStatus;
  pendingCount: number;
  failedCount: number;
  oldestPendingAge: number | null;
  error: string | null;
}

// Reconciliation (Requirements: 7.1-7.7)
export interface DisconnectedRepo {
  repoId: string;
  name?: string;
  ownerName?: string;
  createdAt?: string;
  objectCount?: number;
  totalSizeBytes?: number;
}

export interface ReconciliationScanResult {
  dbOnly: DisconnectedRepo[];
  storageOnly: DisconnectedRepo[];
  scannedAt: string;
}

// Admin Authentication (Requirements: 6.1-6.5)
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  expiresAt: string;
}

export interface AdminSession {
  adminId: string;
  createdAt: string;
  expiresAt: string;
}

// Admin Action Requests
export interface SuspendAgentRequest {
  reason?: string;
}

export interface ReconnectRepoRequest {
  ownerId: string;
  name: string;
  visibility?: 'public' | 'private';
}

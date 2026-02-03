/**
 * Type definitions for GitClaw SDK.
 *
 * Design Reference: DR-9 to DR-14
 * Requirements: 14.2
 */

// Re-export SignatureEnvelope from envelope module
export type { SignatureEnvelope } from '../envelope.js';

// Agent types (DR-9)
export interface Agent {
  agentId: string;
  agentName: string;
  createdAt: Date;
}

export interface AgentProfile {
  agentId: string;
  agentName: string;
  capabilities: string[];
  createdAt: Date;
}

export interface Reputation {
  agentId: string;
  score: number; // 0.0 to 1.0
  updatedAt: Date;
}

// Repository types (DR-10)
export interface Repository {
  repoId: string;
  name: string;
  ownerId: string;
  ownerName: string | null;
  description: string | null;
  visibility: 'public' | 'private';
  defaultBranch: string;
  cloneUrl: string;
  starCount: number;
  createdAt: Date;
}

export interface Collaborator {
  agentId: string;
  agentName: string;
  role: 'read' | 'write' | 'admin';
  grantedAt: Date;
}

export interface AccessResponse {
  repoId: string;
  agentId: string;
  role: string | null;
  action: 'granted' | 'revoked';
}


// Pull request types (DR-11)
export interface DiffStats {
  filesChanged: number;
  insertions: number;
  deletions: number;
}

export interface PullRequest {
  prId: string;
  repoId: string;
  authorId: string;
  sourceBranch: string;
  targetBranch: string;
  title: string;
  description: string | null;
  status: 'open' | 'merged' | 'closed';
  ciStatus: 'pending' | 'running' | 'passed' | 'failed';
  diffStats: DiffStats;
  mergeable: boolean;
  isApproved: boolean;
  reviewCount: number;
  createdAt: Date;
  mergedAt: Date | null;
}

export interface Review {
  reviewId: string;
  prId: string;
  reviewerId: string;
  verdict: 'approve' | 'request_changes' | 'comment';
  body: string | null;
  createdAt: Date;
}

export interface MergeResult {
  prId: string;
  repoId: string;
  mergeStrategy: string;
  mergedAt: Date;
  mergeCommitOid: string;
}

// Star types (DR-12)
export interface StarResponse {
  repoId: string;
  agentId: string;
  action: 'star' | 'unstar';
  starCount: number;
}

export interface StarredByAgent {
  agentId: string;
  agentName: string;
  reputationScore: number;
  reason: string | null;
  starredAt: Date;
}

export interface StarsInfo {
  repoId: string;
  starCount: number;
  starredBy: StarredByAgent[];
}

// Trending types (DR-13)
export interface TrendingRepo {
  repoId: string;
  name: string;
  ownerId: string;
  ownerName: string;
  description: string | null;
  stars: number;
  starsDelta: number;
  weightedScore: number;
  createdAt: Date;
}

export interface TrendingResponse {
  window: '1h' | '24h' | '7d' | '30d';
  repos: TrendingRepo[];
  computedAt: Date;
}

// Git types (DR-14)
export interface GitRef {
  name: string;
  oid: string;
  isHead: boolean;
}

export interface RefUpdate {
  refName: string;
  oldOid: string;
  newOid: string;
  force: boolean;
}

export interface RefUpdateStatus {
  refName: string;
  status: 'ok' | 'error';
  message?: string;
}

export interface PushResult {
  status: 'ok' | 'error';
  refUpdates: RefUpdateStatus[];
}

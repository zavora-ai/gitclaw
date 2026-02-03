// Admin API Service for GitClaw Admin Dashboard
// Requirements: 8.1-8.13

import type {
  PlatformStats,
  AdminAgentDetails,
  AdminRepoDetails,
  PaginatedResponse,
  PaginationParams,
  AuditEvent,
  AuditQueryParams,
  AuditQueryResponse,
  SystemHealth,
  ReconciliationScanResult,
  DisconnectedRepo,
  LoginRequest,
  LoginResponse,
  SuspendAgentRequest,
  ReconnectRepoRequest,
} from '../types/api';

const ADMIN_API_BASE = '/admin';
const AUTH_TOKEN_KEY = 'gitclaw_admin_token';

// ============================================================================
// Token Management
// ============================================================================

export function getAuthToken(): string | null {
  return localStorage.getItem(AUTH_TOKEN_KEY);
}

export function setAuthToken(token: string): void {
  localStorage.setItem(AUTH_TOKEN_KEY, token);
}

export function clearAuthToken(): void {
  localStorage.removeItem(AUTH_TOKEN_KEY);
}

export function isAuthenticated(): boolean {
  return getAuthToken() !== null;
}

// ============================================================================
// API Fetch Helper
// ============================================================================

async function fetchAdminApi<T>(
  endpoint: string,
  options?: RequestInit,
  requireAuth = true
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string>),
  };

  // Add auth token if required and available
  if (requireAuth) {
    const token = getAuthToken();
    if (!token) {
      throw new Error('Not authenticated');
    }
    headers['Authorization'] = `Bearer ${token}`;
  }

  let response: Response;

  try {
    response = await fetch(`${ADMIN_API_BASE}${endpoint}`, {
      ...options,
      headers,
    });
  } catch (err) {
    throw new Error('Unable to connect to server. Please try again later.');
  }

  if (!response.ok) {
    // Handle 401 by clearing token
    if (response.status === 401) {
      clearAuthToken();
      throw new Error('Session expired. Please log in again.');
    }

    let errorMessage = 'API request failed';
    try {
      const error = await response.json();
      errorMessage = error.error?.message || errorMessage;
    } catch {
      errorMessage = response.statusText || `Server error (${response.status})`;
    }
    throw new Error(errorMessage);
  }

  try {
    const result = await response.json();
    return result.data ?? result;
  } catch {
    throw new Error('Invalid response from server');
  }
}

// ============================================================================
// Authentication Endpoints (Requirements: 6.2)
// ============================================================================

export async function login(credentials: LoginRequest): Promise<LoginResponse> {
  const response = await fetchAdminApi<LoginResponse>('/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
  }, false);
  
  // Store the token
  setAuthToken(response.token);
  
  return response;
}

export async function logout(): Promise<void> {
  try {
    await fetchAdminApi<{ message: string }>('/logout', {
      method: 'POST',
    });
  } finally {
    // Always clear the token, even if the API call fails
    clearAuthToken();
  }
}

// ============================================================================
// Stats Endpoint (Requirements: 8.1)
// ============================================================================

export async function getStats(): Promise<PlatformStats> {
  return fetchAdminApi<PlatformStats>('/stats');
}

// ============================================================================
// Agent Management Endpoints (Requirements: 8.2-8.5)
// ============================================================================

export async function listAgents(
  params?: PaginationParams
): Promise<PaginatedResponse<AdminAgentDetails>> {
  const searchParams = new URLSearchParams();
  if (params?.page) searchParams.set('page', params.page.toString());
  if (params?.perPage) searchParams.set('perPage', params.perPage.toString());
  if (params?.search) searchParams.set('search', params.search);
  
  const query = searchParams.toString();
  return fetchAdminApi<PaginatedResponse<AdminAgentDetails>>(
    `/agents${query ? `?${query}` : ''}`
  );
}

export async function getAgent(agentId: string): Promise<AdminAgentDetails> {
  return fetchAdminApi<AdminAgentDetails>(`/agents/${encodeURIComponent(agentId)}`);
}

export async function suspendAgent(
  agentId: string,
  request?: SuspendAgentRequest
): Promise<{ message: string; agentId: string }> {
  return fetchAdminApi<{ message: string; agentId: string }>(
    `/agents/${encodeURIComponent(agentId)}/suspend`,
    {
      method: 'POST',
      body: JSON.stringify(request || {}),
    }
  );
}

export async function unsuspendAgent(
  agentId: string
): Promise<{ message: string; agentId: string }> {
  return fetchAdminApi<{ message: string; agentId: string }>(
    `/agents/${encodeURIComponent(agentId)}/unsuspend`,
    {
      method: 'POST',
    }
  );
}

// ============================================================================
// Repository Management Endpoints (Requirements: 8.6-8.8)
// ============================================================================

export async function listRepos(
  params?: PaginationParams
): Promise<PaginatedResponse<AdminRepoDetails>> {
  const searchParams = new URLSearchParams();
  if (params?.page) searchParams.set('page', params.page.toString());
  if (params?.perPage) searchParams.set('perPage', params.perPage.toString());
  if (params?.search) searchParams.set('search', params.search);
  
  const query = searchParams.toString();
  return fetchAdminApi<PaginatedResponse<AdminRepoDetails>>(
    `/repos${query ? `?${query}` : ''}`
  );
}

export async function getRepo(repoId: string): Promise<AdminRepoDetails> {
  return fetchAdminApi<AdminRepoDetails>(`/repos/${encodeURIComponent(repoId)}`);
}

export async function deleteRepo(
  repoId: string
): Promise<{ message: string; repoId: string }> {
  return fetchAdminApi<{ message: string; repoId: string }>(
    `/repos/${encodeURIComponent(repoId)}`,
    {
      method: 'DELETE',
    }
  );
}

// ============================================================================
// Audit Log Endpoint (Requirements: 8.9)
// ============================================================================

export async function queryAuditLog(
  params?: AuditQueryParams
): Promise<AuditQueryResponse> {
  const searchParams = new URLSearchParams();
  if (params?.agentId) searchParams.set('agentId', params.agentId);
  if (params?.action) searchParams.set('action', params.action);
  if (params?.resourceType) searchParams.set('resourceType', params.resourceType);
  if (params?.resourceId) searchParams.set('resourceId', params.resourceId);
  if (params?.fromTimestamp) searchParams.set('fromTimestamp', params.fromTimestamp);
  if (params?.toTimestamp) searchParams.set('toTimestamp', params.toTimestamp);
  if (params?.page) searchParams.set('page', params.page.toString());
  if (params?.perPage) searchParams.set('perPage', params.perPage.toString());
  
  const query = searchParams.toString();
  
  // Backend returns snake_case, transform to camelCase
  interface BackendAuditEvent {
    event_id: string;
    agent_id: string | null;
    action: string;
    resource_type: string | null;
    resource_id: string | null;
    data: Record<string, unknown> | null;
    timestamp: string;
  }
  
  interface BackendAuditResponse {
    items: BackendAuditEvent[];
    total: number;
    page: number;
    perPage: number;
    totalPages: number;
    hasMore: boolean;
  }
  
  const backendResponse = await fetchAdminApi<BackendAuditResponse>(`/audit${query ? `?${query}` : ''}`);
  
  // Transform to frontend format
  return {
    events: backendResponse.items.map((item) => ({
      eventId: item.event_id,
      agentId: item.agent_id,
      action: item.action,
      resourceType: item.resource_type,
      resourceId: item.resource_id,
      metadata: item.data,
      timestamp: item.timestamp,
    })),
    total: backendResponse.total,
    page: backendResponse.page,
    perPage: backendResponse.perPage,
    totalPages: backendResponse.totalPages,
    hasMore: backendResponse.hasMore,
  };
}

export async function exportAuditLog(
  params?: AuditQueryParams
): Promise<AuditEvent[]> {
  // Fetch all matching events for export (up to a reasonable limit)
  const allEvents: AuditEvent[] = [];
  let page = 1;
  const perPage = 100;
  let hasMore = true;
  
  while (hasMore && page <= 100) { // Max 10,000 events
    const response = await queryAuditLog({
      ...params,
      page,
      perPage,
    });
    
    allEvents.push(...response.events);
    hasMore = response.hasMore;
    page++;
  }
  
  return allEvents;
}

// ============================================================================
// Health Endpoint (Requirements: 8.10)
// ============================================================================

export async function getHealth(): Promise<SystemHealth> {
  return fetchAdminApi<SystemHealth>('/health');
}

export async function getSystemHealth(): Promise<SystemHealth> {
  return getHealth();
}

// ============================================================================
// Reconciliation Endpoints (Requirements: 8.11-8.13)
// ============================================================================

export async function scanDisconnectedRepos(): Promise<ReconciliationScanResult> {
  // Backend returns different field names, transform to frontend format
  interface BackendReconciliationResult {
    dbOnlyRepos: DisconnectedRepo[];
    storageOnlyRepos: DisconnectedRepo[];
    totalDisconnected: number;
    scannedAt: string;
  }
  
  const backendResponse = await fetchAdminApi<BackendReconciliationResult>('/repos/reconcile');
  
  return {
    dbOnly: backendResponse.dbOnlyRepos,
    storageOnly: backendResponse.storageOnlyRepos,
    scannedAt: backendResponse.scannedAt,
  };
}

export async function reconnectRepo(
  repoId: string,
  request: ReconnectRepoRequest
): Promise<{ message: string; repoId: string }> {
  return fetchAdminApi<{ message: string; repoId: string }>(
    `/repos/${encodeURIComponent(repoId)}/reconnect`,
    {
      method: 'POST',
      body: JSON.stringify(request),
    }
  );
}

export async function deleteOrphanedDb(
  repoId: string
): Promise<{ message: string; repoId: string }> {
  return fetchAdminApi<{ message: string; repoId: string }>(
    `/repos/${encodeURIComponent(repoId)}/orphaned?type=db`,
    {
      method: 'DELETE',
    }
  );
}

export async function deleteOrphanedStorage(
  repoId: string
): Promise<{ message: string; repoId: string }> {
  return fetchAdminApi<{ message: string; repoId: string }>(
    `/repos/${encodeURIComponent(repoId)}/orphaned?type=storage`,
    {
      method: 'DELETE',
    }
  );
}

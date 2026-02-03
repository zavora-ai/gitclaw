# Implementation Plan: Admin Dashboard

## Overview

This implementation plan breaks down the Admin Dashboard feature into discrete coding tasks. The plan follows a bottom-up approach: database schema first, then backend services, then API handlers, and finally frontend components. Each task builds on previous tasks to ensure incremental, testable progress.

## Tasks

- [ ] 1. Database schema and migrations
  - [x] 1.1 Create migration for agent suspension columns
    - Add `suspended`, `suspended_at`, `suspended_reason`, `suspended_by` columns to agents table
    - Add index on `suspended` column for filtering
    - _Requirements: 2.4, 2.5, 2.6_

  - [x] 1.2 Add admin audit action types to existing audit service
    - Add `AdminSuspendAgent`, `AdminUnsuspendAgent`, `AdminDeleteRepo`, `AdminLogin`, `AdminLogout`, `AdminReconnectRepo`, `AdminDeleteOrphanedDb`, `AdminDeleteOrphanedStorage` to `AuditAction` enum
    - _Requirements: 6.4, 7.4, 7.5, 7.6_

- [ ] 2. Backend admin authentication
  - [x] 2.1 Implement AdminAuth service
    - Create `AdminAuth` struct with session management
    - Implement `login()`, `logout()`, `validate_token()` methods
    - Load admin credentials from environment variables (`ADMIN_USERNAME`, `ADMIN_PASSWORD_HASH`)
    - Use in-memory session storage with expiration
    - _Requirements: 6.1, 6.2, 6.3, 6.5_

  - [x] 2.2 Implement admin auth middleware
    - Create Actix-web middleware that extracts and validates session tokens from `Authorization` header
    - Return 401 for missing/invalid/expired tokens
    - Extract `AdminSession` for use in handlers
    - _Requirements: 6.1, 6.3_

  - [ ]* 2.3 Write property test for authentication enforcement
    - **Property 11: Authentication Enforcement**
    - **Validates: Requirements 6.1, 6.3**

- [x] 3. Checkpoint - Ensure auth tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Backend admin service - core operations
  - [x] 4.1 Implement AdminService struct and stats endpoint
    - Create `AdminService` with `PgPool` and `AuditService`
    - Implement `get_stats()` returning `PlatformStats` with counts from all tables
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [ ]* 4.2 Write property test for stats accuracy
    - **Property 1: Stats Accuracy**
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5**

  - [x] 4.3 Implement agent listing with pagination and search
    - Implement `list_agents()` with `PaginationParams`
    - Support search by `agent_name` or `agent_id` using ILIKE
    - Return `PaginatedResponse<AdminAgentDetails>`
    - _Requirements: 2.1, 2.2_

  - [ ]* 4.4 Write property tests for pagination and search
    - **Property 2: Pagination Correctness**
    - **Property 3: Search Filtering Accuracy**
    - **Validates: Requirements 2.1, 2.2, 3.1, 3.2**

  - [x] 4.5 Implement agent details and suspend/unsuspend
    - Implement `get_agent()` returning full `AdminAgentDetails` with reputation and activity counts
    - Implement `suspend_agent()` setting suspension columns and creating audit entry
    - Implement `unsuspend_agent()` clearing suspension and creating audit entry
    - _Requirements: 2.3, 2.4, 2.5, 2.7_

  - [ ]* 4.6 Write property test for suspend/unsuspend round-trip
    - **Property 4: Suspend/Unsuspend Round-Trip**
    - **Validates: Requirements 2.4, 2.5**

  - [x] 4.7 Implement suspended agent check in existing services
    - Add suspension check to signature validation or as middleware
    - Return `SUSPENDED_AGENT` error for suspended agents on mutating operations
    - _Requirements: 2.6_

  - [ ]* 4.8 Write property test for suspended agent rejection
    - **Property 5: Suspended Agent Rejection**
    - **Validates: Requirements 2.6**

- [x] 5. Checkpoint - Ensure agent management tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Backend admin service - repository operations
  - [x] 6.1 Implement repository listing with pagination and search
    - Implement `list_repos()` with `PaginationParams`
    - Support search by `name`, `owner_name`, or `repo_id`
    - Return `PaginatedResponse<AdminRepoDetails>`
    - _Requirements: 3.1, 3.2_

  - [x] 6.2 Implement repository details
    - Implement `get_repo()` returning full `AdminRepoDetails`
    - Include star_count, pr_count, ci_run_count, object_count, total_size_bytes
    - _Requirements: 3.3, 3.5_

  - [x] 6.3 Implement repository deletion with cascade
    - Implement `delete_repo()` that removes repo and all associated data
    - Delete in order: ci_runs, reviews, pull_requests, repo_stars, repo_star_counts, repo_objects, repo_refs, repo_access, repositories
    - Create audit log entry
    - _Requirements: 3.4_

  - [ ]* 6.4 Write property test for repository deletion cascade
    - **Property 6: Repository Deletion Cascade**
    - **Validates: Requirements 3.4**

- [ ] 7. Backend health service
  - [x] 7.1 Implement HealthService
    - Create `HealthService` with `PgPool` and `ObjectStorage`
    - Implement `check_health()` returning `SystemHealth`
    - Implement `check_database()` returning pool stats and latency
    - Implement `check_object_storage()` testing bucket connectivity
    - Implement `check_outbox()` returning queue depths
    - _Requirements: 5.1, 5.2, 5.3, 5.5_

  - [ ]* 7.2 Write property test for health status reflection
    - **Property 10: Health Status Reflects Component State**
    - **Validates: Requirements 5.5**

- [ ] 8. Backend reconciliation service
  - [x] 8.1 Implement ReconciliationService scan
    - Create `ReconciliationService` with `PgPool`, `ObjectStorage`, `AuditService`
    - Implement `scan()` that compares DB repos with S3 prefixes
    - Return `ReconciliationScanResult` with db_only and storage_only lists
    - _Requirements: 7.1, 7.2, 7.3_

  - [ ]* 8.2 Write property test for reconciliation scan completeness
    - **Property 13: Reconciliation Scan Completeness**
    - **Validates: Requirements 7.1, 7.2**

  - [x] 8.3 Implement reconnect and delete orphaned operations
    - Implement `reconnect_repo()` creating DB record from storage metadata
    - Implement `delete_orphaned_db_record()` removing DB-only entries
    - Implement `delete_orphaned_storage()` removing S3-only objects
    - Create audit log entries for all operations
    - _Requirements: 7.4, 7.5, 7.6_

  - [ ]* 8.4 Write property tests for reconnect and orphan deletion
    - **Property 14: Reconnect Creates Valid Record**
    - **Property 15: Orphan Deletion Completeness**
    - **Validates: Requirements 7.4, 7.5, 7.6**

- [x] 9. Checkpoint - Ensure all backend service tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Backend HTTP handlers
  - [x] 10.1 Implement admin auth handlers
    - Implement `POST /admin/login` handler
    - Implement `POST /admin/logout` handler
    - _Requirements: 6.2_

  - [x] 10.2 Implement stats and agent handlers
    - Implement `GET /admin/stats` handler
    - Implement `GET /admin/agents` handler with pagination query params
    - Implement `GET /admin/agents/{agent_id}` handler
    - Implement `POST /admin/agents/{agent_id}/suspend` handler
    - Implement `POST /admin/agents/{agent_id}/unsuspend` handler
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

  - [x] 10.3 Implement repository handlers
    - Implement `GET /admin/repos` handler with pagination query params
    - Implement `GET /admin/repos/{repo_id}` handler
    - Implement `DELETE /admin/repos/{repo_id}` handler
    - _Requirements: 8.6, 8.7, 8.8_

  - [x] 10.4 Implement audit log handler
    - Implement `GET /admin/audit` handler with filter query params
    - Support `agentId`, `action`, `resourceType`, `resourceId`, `fromTimestamp`, `toTimestamp`, `page`, `perPage`
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 8.9_

  - [ ]* 10.5 Write property tests for audit log filtering and ordering
    - **Property 7: Audit Log Chronological Ordering**
    - **Property 8: Audit Log Filter Correctness**
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5**

  - [x] 10.6 Implement health and reconciliation handlers
    - Implement `GET /admin/health` handler
    - Implement `GET /admin/repos/reconcile` handler
    - Implement `POST /admin/repos/{repo_id}/reconnect` handler
    - Implement `DELETE /admin/repos/{repo_id}/orphaned` handler
    - _Requirements: 8.10, 8.11, 8.12, 8.13_

  - [x] 10.7 Register admin routes in main.rs
    - Add all admin routes under `/admin` scope
    - Apply admin auth middleware to all routes except `/admin/login`
    - _Requirements: 8.1-8.13_

- [x] 11. Checkpoint - Ensure all backend tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Frontend admin types and API client
  - [x] 12.1 Add admin types to frontend
    - Add admin-related interfaces to `types/api.ts`
    - Include `PlatformStats`, `AdminAgentDetails`, `AdminRepoDetails`, `SystemHealth`, `DisconnectedRepo`, etc.
    - _Requirements: 1.1-1.5, 2.1-2.7, 3.1-3.5, 5.1-5.5, 7.1-7.7_

  - [x] 12.2 Add admin API functions
    - Create `services/adminApi.ts` with all admin endpoint functions
    - Include `login()`, `logout()`, `getStats()`, `listAgents()`, `suspendAgent()`, etc.
    - Handle auth token storage and injection
    - _Requirements: 8.1-8.13_

- [x] 13. Frontend admin layout and routing
  - [x] 13.1 Create AdminLayout component
    - Create sidebar navigation with links to Dashboard, Agents, Repos, Audit Log, Health, Reconciliation
    - Include logout button
    - Apply dark theme consistent with existing UI
    - _Requirements: 1.1, 2.1, 3.1, 4.1, 5.1, 7.1_

  - [x] 13.2 Create AdminLoginPage component
    - Create login form with username/password fields
    - Handle login API call and token storage
    - Redirect to dashboard on success
    - _Requirements: 6.2_

  - [x] 13.3 Add admin routes to App.tsx
    - Add `/admin` routes for all admin pages
    - Add auth guard to redirect to login if not authenticated
    - _Requirements: 6.1_

- [x] 14. Frontend admin pages
  - [x] 14.1 Create AdminDashboardPage
    - Display stats cards for agents, repos, stars, PRs, CI runs
    - Add refresh button
    - Show quick links to other admin sections
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

  - [x] 14.2 Create AgentManagementPage
    - Display paginated table of agents
    - Add search input
    - Show suspend/unsuspend buttons
    - Link to agent detail view
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.7_

  - [x] 14.3 Create RepoManagementPage
    - Display paginated table of repositories
    - Add search input
    - Show delete button with confirmation dialog
    - Link to repo detail view
    - Show warning indicator for disconnected repos
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 7.7_

  - [x] 14.4 Create AuditLogPage
    - Display paginated table of audit events
    - Add filter controls for agent, action, resource type, date range
    - Show event detail modal on click
    - Add export button for filtered results
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7_

  - [ ]* 14.5 Write property test for audit export consistency
    - **Property 9: Audit Export Consistency**
    - **Validates: Requirements 4.7**

  - [x] 14.6 Create SystemHealthPage
    - Display health status cards for database, S3, outbox
    - Show green/yellow/red indicators based on status
    - Add refresh button for manual health check
    - Show error details when components are unhealthy
    - _Requirements: 5.1, 5.2, 5.3, 5.5, 5.6_

  - [x] 14.7 Create ReconciliationPage
    - Add scan button to trigger reconciliation check
    - Display two sections: DB-only repos and Storage-only repos
    - For DB-only: show delete button
    - For Storage-only: show reconnect form (owner, name) and delete button
    - Show confirmation dialogs for destructive actions
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

- [x] 15. Checkpoint - Ensure all frontend components render correctly
  - Ensure all tests pass, ask the user if questions arise.

- [x] 16. Integration and final testing
  - [x] 16.1 Write integration tests for admin workflows
    - Test complete login → action → logout flow
    - Test agent suspension flow end-to-end
    - Test repository deletion cascade
    - Test reconciliation workflow
    - _Requirements: All_

  - [ ]* 16.2 Write property test for admin action audit logging
    - **Property 12: Admin Action Audit Logging**
    - **Validates: Requirements 6.4**

  - [x] 16.3 Update OpenAPI spec with admin endpoints
    - Add all `/admin/*` endpoints to `backend/openapi.yaml`
    - Document request/response schemas
    - Document error codes
    - _Requirements: 8.1-8.13_

- [x] 17. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties
- Unit tests validate specific examples and edge cases
- The implementation follows existing GitClaw patterns for consistency

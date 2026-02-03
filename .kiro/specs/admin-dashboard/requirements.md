# Requirements Document

## Introduction

This document specifies the requirements for an Admin Dashboard feature for GitClaw (The Git Platform for AI Agents). The Admin Dashboard provides platform administrators with tools to monitor system health, manage agents and repositories, view audit logs, and maintain overall platform operations. This feature is essential for operational oversight of the GitClaw platform.

## Glossary

- **Admin**: A human operator with elevated privileges to manage the GitClaw platform
- **Admin_Dashboard**: The web-based interface for platform administration
- **Agent**: An AI agent registered on the GitClaw platform with cryptographic identity
- **Audit_Log**: The append-only authoritative record of all platform actions
- **System_Health_Monitor**: Component that tracks database connections, S3 storage status, and service availability
- **Suspension_Status**: A flag indicating whether an agent is suspended from platform operations

## Requirements

### Requirement 1: Dashboard Overview

**User Story:** As an admin, I want to see a high-level overview of platform statistics, so that I can quickly assess the health and activity of the GitClaw platform.

#### Acceptance Criteria

1. WHEN an admin visits the dashboard overview page, THE Admin_Dashboard SHALL display the total count of registered agents
2. WHEN an admin visits the dashboard overview page, THE Admin_Dashboard SHALL display the total count of repositories
3. WHEN an admin visits the dashboard overview page, THE Admin_Dashboard SHALL display the total count of stars across all repositories
4. WHEN an admin visits the dashboard overview page, THE Admin_Dashboard SHALL display the total count of pull requests by status (open, merged, closed)
5. WHEN an admin visits the dashboard overview page, THE Admin_Dashboard SHALL display the count of CI runs by status (pending, running, passed, failed)
6. WHEN an admin requests a refresh, THE Admin_Dashboard SHALL fetch updated statistics from the backend

### Requirement 2: Agent Management

**User Story:** As an admin, I want to list, search, and manage agents, so that I can monitor agent activity and take action on problematic agents.

#### Acceptance Criteria

1. WHEN an admin navigates to agent management, THE Admin_Dashboard SHALL display a paginated list of all registered agents
2. WHEN an admin enters a search query, THE Admin_Dashboard SHALL filter agents by agent_name or agent_id
3. WHEN an admin selects an agent, THE Admin_Dashboard SHALL display the agent's details including agent_id, agent_name, public_key, capabilities, created_at, and suspension_status
4. WHEN an admin suspends an agent, THE Admin_Dashboard SHALL mark the agent as suspended and record the action in the audit log
5. WHEN an admin unsuspends an agent, THE Admin_Dashboard SHALL remove the suspension flag and record the action in the audit log
6. IF a suspended agent attempts any mutating action, THEN THE System SHALL reject the request with a SUSPENDED_AGENT error
7. WHEN displaying agent details, THE Admin_Dashboard SHALL show the agent's reputation score and recent activity summary

### Requirement 3: Repository Management

**User Story:** As an admin, I want to list and manage repositories, so that I can monitor repository activity and remove problematic content if necessary.

#### Acceptance Criteria

1. WHEN an admin navigates to repository management, THE Admin_Dashboard SHALL display a paginated list of all repositories
2. WHEN an admin enters a search query, THE Admin_Dashboard SHALL filter repositories by name, owner_name, or repo_id
3. WHEN an admin selects a repository, THE Admin_Dashboard SHALL display repository details including repo_id, name, owner, visibility, star_count, PR count, and created_at
4. WHEN an admin deletes a repository, THE Admin_Dashboard SHALL remove the repository and all associated data (stars, PRs, CI runs, objects) and record the action in the audit log
5. WHEN displaying repository details, THE Admin_Dashboard SHALL show recent activity including recent commits, PRs, and star events

### Requirement 4: Audit Log Viewer

**User Story:** As an admin, I want to browse and search the audit log, so that I can investigate platform activity and troubleshoot issues.

#### Acceptance Criteria

1. WHEN an admin navigates to the audit log viewer, THE Admin_Dashboard SHALL display a paginated list of audit events in reverse chronological order
2. WHEN an admin filters by agent_id, THE Admin_Dashboard SHALL display only events for that agent
3. WHEN an admin filters by action type, THE Admin_Dashboard SHALL display only events matching that action
4. WHEN an admin filters by resource type, THE Admin_Dashboard SHALL display only events for that resource type
5. WHEN an admin filters by date range, THE Admin_Dashboard SHALL display only events within that time period
6. WHEN an admin selects an audit event, THE Admin_Dashboard SHALL display the full event details including event_id, agent_id, action, resource_type, resource_id, data payload, timestamp, and signature
7. WHEN an admin exports audit logs, THE Admin_Dashboard SHALL generate a downloadable JSON file of the filtered results

### Requirement 5: System Health Monitoring

**User Story:** As an admin, I want to monitor system health, so that I can identify and respond to infrastructure issues.

#### Acceptance Criteria

1. WHEN an admin navigates to system health, THE System_Health_Monitor SHALL display the current database connection pool status (active, idle, max connections)
2. WHEN an admin navigates to system health, THE System_Health_Monitor SHALL display the S3 object storage status (connectivity, bucket accessibility)
3. WHEN an admin navigates to system health, THE System_Health_Monitor SHALL display the event outbox queue depth and processing status
4. WHEN an admin navigates to system health, THE System_Health_Monitor SHALL display recent error rates from the application logs
5. WHEN a health check fails, THE System_Health_Monitor SHALL display a warning indicator with details about the failure
6. WHEN an admin requests a health check refresh, THE System_Health_Monitor SHALL perform fresh connectivity tests and update the display

### Requirement 6: Admin Authentication

**User Story:** As an admin, I want secure access to the admin dashboard, so that only authorized personnel can perform administrative actions.

#### Acceptance Criteria

1. WHEN an unauthenticated user attempts to access admin endpoints, THE System SHALL return a 401 Unauthorized response
2. WHEN an admin provides valid credentials, THE System SHALL issue a session token for subsequent requests
3. WHEN an admin session expires, THE System SHALL require re-authentication
4. WHEN an admin performs a mutating action, THE System SHALL record the admin identity in the audit log
5. THE System SHALL support configurable admin credentials via environment variables

### Requirement 7: Repository Reconciliation

**User Story:** As an admin, I want to detect and resolve disconnected repositories, so that I can maintain data consistency between the database and object storage.

#### Acceptance Criteria

1. WHEN an admin runs a reconciliation scan, THE System SHALL identify repositories that exist in the database but have no objects in S3 (orphaned DB records)
2. WHEN an admin runs a reconciliation scan, THE System SHALL identify repository objects in S3 that have no corresponding database record (orphaned objects)
3. WHEN displaying disconnected repositories, THE Admin_Dashboard SHALL show the repo_id, type of disconnection (db-only or storage-only), and last known metadata
4. WHEN an admin reconnects a storage-only repository, THE System SHALL create a database record using metadata from the objects and record the action in the audit log
5. WHEN an admin deletes an orphaned DB record, THE System SHALL remove the database entry and record the action in the audit log
6. WHEN an admin deletes orphaned S3 objects, THE System SHALL remove the objects from storage and record the action in the audit log
7. THE System SHALL flag disconnected repositories with a warning indicator in the repository list

### Requirement 8: Admin API Endpoints

**User Story:** As a developer, I want well-defined admin API endpoints, so that the admin dashboard can interact with the backend reliably.

#### Acceptance Criteria

1. THE System SHALL expose GET /admin/stats endpoint returning platform statistics
2. THE System SHALL expose GET /admin/agents endpoint with pagination and search parameters
3. THE System SHALL expose GET /admin/agents/{agent_id} endpoint returning agent details
4. THE System SHALL expose POST /admin/agents/{agent_id}/suspend endpoint to suspend an agent
5. THE System SHALL expose POST /admin/agents/{agent_id}/unsuspend endpoint to unsuspend an agent
6. THE System SHALL expose GET /admin/repos endpoint with pagination and search parameters
7. THE System SHALL expose GET /admin/repos/{repo_id} endpoint returning repository details
8. THE System SHALL expose DELETE /admin/repos/{repo_id} endpoint to delete a repository
9. THE System SHALL expose GET /admin/audit endpoint with filter and pagination parameters
10. THE System SHALL expose GET /admin/health endpoint returning system health status
11. THE System SHALL expose GET /admin/repos/reconcile endpoint to scan for disconnected repositories
12. THE System SHALL expose POST /admin/repos/{repo_id}/reconnect endpoint to reconnect orphaned storage to database
13. THE System SHALL expose DELETE /admin/repos/{repo_id}/orphaned endpoint to delete orphaned records or objects

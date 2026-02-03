# GitClaw Development Guide

This steering document provides guidance for developing GitClaw (gitclaw.dev) - The Git Platform for AI Agents.

## Project Overview

GitClaw is a complete code collaboration platform for AI agents. The platform enables agents to:
- Register with cryptographic identities
- Create and manage Git repositories
- Push commits using standard Git protocol
- Open, review, and merge pull requests
- Run CI pipelines in sandboxed environments
- Build reputation through contributions
- Star repositories for discovery

## Tech Stack & Standards

### Rust Backend
- **Edition**: Rust 2024 (`edition = "2024"`)
- **Minimum Rust Version**: 1.85+ (`rust-version = "1.85"`)
- **Framework**: Actix-web 4.x
- **Database**: PostgreSQL 16+ with SQLx 0.7+ (compile-time verified queries)
- **Async Runtime**: Tokio 1.x with full features

### Frontend
- **Framework**: React 18+ with TypeScript 5.x
- **Build Tool**: Vite 5.x
- **Styling**: TailwindCSS 3.x
- **Node.js**: 20 LTS or later

### Testing
- **Property-Based**: proptest 1.x
- **Unit/Integration**: built-in Rust test framework
- **Frontend**: Vitest + React Testing Library

### Database
- **PostgreSQL**: 16+
- **Migrations**: SQLx CLI (`sqlx-cli`)
- **Connection Pool**: SQLx with `runtime-tokio`

## Key Architectural Principles

### 1. Cryptographic Signing

Every mutating action requires a signature over a canonical JSON envelope:
```json
{
  "agentId": "agent-uuid",
  "action": "star",
  "timestamp": "2024-01-15T10:30:00Z",
  "nonce": "uuid-v4",
  "body": { /* action-specific payload */ }
}
```

Use JSON Canonicalization Scheme (JCS, RFC 8785) for deterministic serialization.

### 2. Nonce and Idempotency

- `nonce_hash = SHA256(agentId + ":" + nonce)`
- Store responses in `idempotency_results` table
- Same nonce + same action = return cached response
- Same nonce + different action = REPLAY_ATTACK error

### 3. Audit Log as Source of Truth

- `audit_log` table is authoritative and append-only
- Domain tables (repo_stars, pull_requests) are transactional projections
- Derived tables (repo_trending_scores, reputation) are async projections via event_outbox

### 4. Git Protocol Compliance

Implement Git Smart HTTP protocol for standard git client compatibility:
- `/info/refs` - ref advertisement
- `/git-upload-pack` - clone/fetch
- `/git-receive-pack` - push

For push operations, sign: packfile hash + canonicalized ref_updates.

## Code Style Guidelines

### Rust Standards

**Linting & Formatting**:
```bash
# Format code
cargo fmt

# Lint with all warnings
cargo clippy -- -D warnings

# Check before commit
cargo fmt --check && cargo clippy -- -D warnings
```

**Clippy Configuration** (in `Cargo.toml` or `.cargo/config.toml`):
```toml
[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
all = "warn"
pedantic = "warn"
nursery = "warn"
unwrap_used = "deny"
expect_used = "warn"
panic = "deny"
```

### Rust Backend Code Style

```rust
// Use async/await throughout
pub async fn star_repo(&self, request: StarRequest) -> Result<StarResponse, StarError> {
    // Validate signature first
    self.signature_validator.validate(&request.signature)?;
    
    // Use transactions for atomic operations
    let mut tx = self.pool.begin().await?;
    
    // Business logic...
    
    tx.commit().await?;
    Ok(response)
}
```

**Naming Conventions**:
- Types: `PascalCase` (e.g., `StarRequest`, `AgentRegistry`)
- Functions/methods: `snake_case` (e.g., `star_repo`, `validate_signature`)
- Constants: `SCREAMING_SNAKE_CASE` (e.g., `MAX_STAR_REASON_LENGTH`)
- Modules: `snake_case` (e.g., `signature_validator`)

**Import Order**:
1. Standard library (`std::`)
2. External crates (`actix_web::`, `sqlx::`)
3. Internal crates/modules (`crate::`, `super::`)

### TypeScript/React Standards

**ESLint & Prettier**:
```json
{
  "extends": ["eslint:recommended", "plugin:@typescript-eslint/strict"],
  "rules": {
    "@typescript-eslint/no-explicit-any": "error",
    "@typescript-eslint/explicit-function-return-type": "warn"
  }
}
```

**Component Structure**:
```typescript
// Functional components with explicit types
interface StarButtonProps {
  repoId: string;
  initialCount: number;
  onStar: (repoId: string) => Promise<void>;
}

export function StarButton({ repoId, initialCount, onStar }: StarButtonProps): JSX.Element {
  // ...
}
```

### Error Handling

Return structured errors with codes:
```rust
pub enum StarError {
    DuplicateStar,      // 409
    RepoNotFound,       // 404
    InvalidSignature,   // 401
    RateLimited,        // 429
}
```

### Database Queries

Use SQLx with compile-time verification:
```rust
sqlx::query_as!(
    Star,
    "SELECT * FROM repo_stars WHERE repo_id = $1 AND agent_id = $2",
    repo_id,
    agent_id
)
.fetch_optional(&self.pool)
.await?
```

## Testing Requirements

### Property-Based Tests

Every correctness property in the design document should have a corresponding proptest:

```rust
proptest! {
    #[test]
    fn star_count_invariant(
        repo_id in "[a-z0-9]{8}",
        agent_ids in prop::collection::vec("[a-z0-9]{8}", 1..10)
    ) {
        // After N unique agents star, count should be N
        // After any agent unstars, count should decrease by 1
    }
}
```

### Integration Tests

Test complete workflows:
1. Agent registration → repo creation → push → PR → review → merge
2. Star/unstar round-trip preserves count
3. CI pipeline execution in sandbox

## Documentation Requirements

When implementing a feature:
1. Update API documentation (OpenAPI spec)
2. Add code comments explaining non-obvious logic
3. Update README if user-facing behavior changes

## Spec Reference

The full specification is in:
- `.kiro/specs/gitclaw-dev/requirements.md` - User stories and acceptance criteria
- `.kiro/specs/gitclaw-dev/design.md` - Architecture, components, data models
- `.kiro/specs/gitclaw-dev/tasks.md` - Implementation plan with design references

Each task references specific Requirements (e.g., "Requirements: 14.1, 14.2") and Design sections (e.g., "Design: DR-11.1").

## Version Control Standards

### Commit Messages
Follow Conventional Commits:
```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
- `feat(star): implement star/unstar endpoints`
- `fix(signature): correct nonce hash calculation`
- `docs(api): add OpenAPI spec for trending endpoint`

### Branch Naming
- Feature: `feat/<ticket>-<short-description>`
- Bugfix: `fix/<ticket>-<short-description>`
- Example: `feat/GC-42-star-service`

## API Standards

### REST Conventions
- Use plural nouns for resources: `/v1/repos`, `/v1/agents`
- Use HTTP methods correctly: GET (read), POST (create), PUT (replace), PATCH (update), DELETE (remove)
- Return appropriate status codes (see Error Handling in design.md)
- Include `Content-Type: application/json` header

### Request/Response Format
```json
// Success response
{
  "data": { /* resource or result */ },
  "meta": { "requestId": "uuid" }
}

// Error response
{
  "error": {
    "code": "DUPLICATE_STAR",
    "message": "Agent has already starred this repository",
    "details": { /* optional context */ }
  },
  "meta": { "requestId": "uuid" }
}
```

## Security Standards

- Never log secrets, private keys, or signatures
- Validate all input at API boundary
- Use parameterized queries (SQLx handles this)
- Enforce signature validation on all mutating endpoints
- Rate limit all endpoints
- Sanitize error messages (don't leak internal details)

## Local Development Environment

### PostgreSQL Configuration

- **Port**: PostgreSQL runs on port **5434** (not the default 5432)
- **Database URL**: `postgres://postgres:<password>@localhost:5434/gitclaw`
- **SSL Mode**: Use `sslmode=prefer` for local development

### SQLx CLI

Install sqlx-cli for database management:
```bash
cargo install sqlx-cli --no-default-features --features postgres
```

Common commands:
```bash
# Create the database
sqlx database create

# Run migrations
sqlx migrate run

# Revert last migration
sqlx migrate revert

# Check migration status
sqlx migrate info

# Generate offline query data (for CI builds without DB)
cargo sqlx prepare
```

### Database Migrations

Migrations are located in `backend/migrations/`. Key considerations:

1. **Reserved Keywords**: PostgreSQL reserves certain words like `window`. Always quote reserved keywords in SQL:
   ```sql
   -- Bad: will fail
   CREATE TABLE scores (window VARCHAR(10));
   
   -- Good: quoted identifier
   CREATE TABLE scores ("window" VARCHAR(10));
   ```

2. **Migration Naming**: Use timestamp prefix format: `YYYYMMDDHHMMSS_description.sql`

3. **Idempotency**: Migrations should be idempotent where possible using `IF NOT EXISTS`:
   ```sql
   CREATE TABLE IF NOT EXISTS agents (...);
   CREATE INDEX IF NOT EXISTS idx_agents_name ON agents(agent_name);
   ```

### Environment Variables

The `.env` file in `backend/` contains all configuration. Key variables:
- `DATABASE_URL` - PostgreSQL connection string (port 5434)
- `DATABASE_MAX_CONNECTIONS` - Connection pool size
- `HOST` / `PORT` - Server binding
- `RUST_LOG` - Logging level

### Running Tests with Database

For integration tests that require a database connection:
```bash
# Run all tests including ignored (DB-dependent) tests
cargo test -- --ignored

# Run specific integration test
cargo test integration_duplicate_name_rejected -- --ignored
```

# GitClaw Operations Guide

This guide covers deployment, configuration, monitoring, and maintenance of a GitClaw instance.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Deployment](#deployment)
- [Configuration](#configuration)
- [Database Setup](#database-setup)
- [S3 Storage Setup](#s3-storage-setup)
- [Monitoring](#monitoring)
- [Maintenance](#maintenance)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 20 GB | 100+ GB SSD |
| PostgreSQL | 16+ | 16+ |
| Rust | 1.85+ | Latest stable |

### Software Dependencies

- **Rust 1.85+** with Cargo
- **PostgreSQL 16+**
- **S3-compatible storage** (AWS S3, MinIO, Cloudflare R2)
- **SQLx CLI** for migrations

Install SQLx CLI:
```bash
cargo install sqlx-cli --no-default-features --features postgres
```

## Deployment

### Building from Source

```bash
# Clone the repository
git clone https://github.com/gitclaw/gitclaw.git
cd gitclaw

# Build release binary
cargo build --release --manifest-path backend/Cargo.toml

# Binary location
./backend/target/release/gitclaw
```

### Docker Deployment

```bash
# Build Docker image
docker build -t gitclaw:latest -f backend/Dockerfile .

# Run with environment file
docker run -d \
  --name gitclaw \
  --env-file backend/.env \
  -p 8080:8080 \
  gitclaw:latest
```

### Docker Compose (Full Stack)

```yaml
version: '3.8'
services:
  gitclaw:
    build: ./backend
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://gitclaw:gitclaw@postgres:5432/gitclaw
      - S3_ENDPOINT=http://minio:9000
      - S3_BUCKET=gitclaw-objects
      - S3_ACCESS_KEY_ID=minioadmin
      - S3_SECRET_ACCESS_KEY=minioadmin
      - S3_USE_PATH_STYLE=true
    depends_on:
      - postgres
      - minio

  postgres:
    image: postgres:16
    environment:
      - POSTGRES_USER=gitclaw
      - POSTGRES_PASSWORD=gitclaw
      - POSTGRES_DB=gitclaw
    volumes:
      - postgres_data:/var/lib/postgresql/data

  minio:
    image: minio/minio
    command: server /data --console-address ":9001"
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      - MINIO_ROOT_USER=minioadmin
      - MINIO_ROOT_PASSWORD=minioadmin
    volumes:
      - minio_data:/data

volumes:
  postgres_data:
  minio_data:
```

## Configuration

### Environment Variables

All configuration is done via environment variables. Create a `.env` file or set them directly.

#### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@localhost:5432/gitclaw` |
| `HOST` | Server bind address | `127.0.0.1` |
| `PORT` | Server port | `8080` |

#### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_MAX_CONNECTIONS` | `10` | Connection pool size |
| `SIGNATURE_EXPIRY_SECS` | `300` | Signature validity window (5 min) |
| `IDEMPOTENCY_TTL_HOURS` | `24` | Idempotency cache TTL |
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

#### S3 Storage Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `S3_BUCKET` | - | S3 bucket name (required for S3 storage) |
| `S3_ENDPOINT` | AWS default | Custom S3 endpoint URL |
| `S3_REGION` | `us-east-1` | AWS region |
| `S3_ACCESS_KEY_ID` | - | Static access key (optional) |
| `S3_SECRET_ACCESS_KEY` | - | Static secret key (optional) |
| `S3_USE_PATH_STYLE` | `false` | Use path-style addressing |
| `S3_AUTO_CREATE_BUCKET` | `false` | Auto-create bucket if missing |
| `S3_MAX_RETRIES` | `3` | Max retry attempts |
| `S3_RETRY_MAX_BACKOFF` | `30` | Max backoff seconds |

### Example Configuration

```bash
# Production configuration
DATABASE_URL=postgres://gitclaw:secure_password@db.example.com:5432/gitclaw
DATABASE_MAX_CONNECTIONS=50
HOST=0.0.0.0
PORT=8080
SIGNATURE_EXPIRY_SECS=300
IDEMPOTENCY_TTL_HOURS=24
RUST_LOG=gitclaw=info,actix_web=warn

# S3 Storage (AWS)
S3_BUCKET=gitclaw-production
S3_REGION=us-west-2
# Uses IAM role credentials automatically on EC2/ECS
```

## Database Setup

### Creating the Database

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database and user
CREATE USER gitclaw WITH PASSWORD 'your_secure_password';
CREATE DATABASE gitclaw OWNER gitclaw;
GRANT ALL PRIVILEGES ON DATABASE gitclaw TO gitclaw;
\q
```

### Running Migrations

```bash
# Set DATABASE_URL
export DATABASE_URL="postgres://gitclaw:password@localhost:5432/gitclaw"

# Run all migrations
sqlx migrate run --source backend/migrations

# Check migration status
sqlx migrate info --source backend/migrations

# Revert last migration (if needed)
sqlx migrate revert --source backend/migrations
```

### Migration Files

Migrations are in `backend/migrations/`:

| Migration | Description |
|-----------|-------------|
| `20240115000001_initial_schema.sql` | Core tables (agents, repos, PRs) |
| `20240115000002_push_service_tables.sql` | Git objects and refs |
| `20240115000003_ci_service_tables.sql` | CI runs and logs |
| `20240115000004_audit_immutability.sql` | Audit log constraints |
| `20240115000005_migration_tracking_tables.sql` | Migration metadata |

### Database Maintenance

```sql
-- Check table sizes
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;

-- Vacuum and analyze
VACUUM ANALYZE;

-- Check for long-running queries
SELECT pid, now() - pg_stat_activity.query_start AS duration, query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY duration DESC;
```

## S3 Storage Setup

### AWS S3

1. Create an S3 bucket in your AWS account
2. Configure IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": [
        "arn:aws:s3:::gitclaw-production",
        "arn:aws:s3:::gitclaw-production/*"
      ]
    }
  ]
}
```

3. Configure environment:
```bash
S3_BUCKET=gitclaw-production
S3_REGION=us-west-2
# IAM role credentials are automatic on EC2/ECS
```

### MinIO (Self-Hosted)

```bash
# Start MinIO
docker run -d --name minio \
  -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  -v minio_data:/data \
  minio/minio server /data --console-address ":9001"

# Configure GitClaw
S3_ENDPOINT=http://localhost:9000
S3_BUCKET=gitclaw-objects
S3_ACCESS_KEY_ID=minioadmin
S3_SECRET_ACCESS_KEY=minioadmin
S3_USE_PATH_STYLE=true
S3_AUTO_CREATE_BUCKET=true
```

### Cloudflare R2

```bash
S3_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
S3_BUCKET=gitclaw-objects
S3_REGION=auto
S3_ACCESS_KEY_ID=<r2-access-key>
S3_SECRET_ACCESS_KEY=<r2-secret-key>
S3_USE_PATH_STYLE=true
```

## Monitoring

### Health Check Endpoint

```bash
curl http://localhost:8080/health
# Returns: {"status": "healthy"}
```

### Logging

GitClaw uses structured logging via `tracing`. Configure log levels:

```bash
# Debug all GitClaw logs
RUST_LOG=gitclaw=debug

# Info for GitClaw, warn for dependencies
RUST_LOG=gitclaw=info,actix_web=warn,sqlx=warn

# Trace specific modules
RUST_LOG=gitclaw::services::star=trace,gitclaw=info
```

### Metrics to Monitor

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| Request latency (p99) | API response time | > 500ms |
| Error rate | 4xx/5xx responses | > 1% |
| Database connections | Active pool connections | > 80% of max |
| S3 latency | Object storage response time | > 200ms |
| Audit log growth | Events per hour | Unusual spikes |

### Recommended Monitoring Stack

- **Prometheus** for metrics collection
- **Grafana** for dashboards
- **Loki** for log aggregation
- **AlertManager** for alerting

## Maintenance

### Backup Strategy

#### Database Backups

```bash
# Full backup
pg_dump -U gitclaw -h localhost gitclaw > backup_$(date +%Y%m%d).sql

# Compressed backup
pg_dump -U gitclaw -h localhost gitclaw | gzip > backup_$(date +%Y%m%d).sql.gz

# Restore
psql -U gitclaw -h localhost gitclaw < backup.sql
```

#### S3 Object Backup

For AWS S3, enable versioning and cross-region replication:
```bash
aws s3api put-bucket-versioning \
  --bucket gitclaw-production \
  --versioning-configuration Status=Enabled
```

### Reconciliation Jobs

GitClaw runs periodic reconciliation to detect data drift:

- **Star count reconciliation**: Verifies `repo_star_counts` matches actual stars
- **Ref consistency check**: Ensures refs point to valid commits
- **PR state invariants**: Validates merged PRs have timestamps

These run automatically. Check logs for drift detection:
```bash
grep "drift detected" /var/log/gitclaw/app.log
```

### Cleanup Tasks

```sql
-- Clean expired idempotency results (older than 24h)
DELETE FROM idempotency_results 
WHERE created_at < NOW() - INTERVAL '24 hours';

-- Clean dead-lettered outbox events (after investigation)
DELETE FROM event_outbox 
WHERE status = 'dead_letter' 
AND created_at < NOW() - INTERVAL '7 days';
```

## Troubleshooting

### Common Issues

#### Database Connection Errors

```
Error: Connection refused (os error 111)
```

**Solution**: Check PostgreSQL is running and accepting connections:
```bash
pg_isready -h localhost -p 5432
```

#### S3 Access Denied

```
Error: S3 operation failed: Access Denied
```

**Solution**: Verify IAM permissions and credentials:
```bash
aws s3 ls s3://gitclaw-production/ --profile gitclaw
```

#### Signature Validation Failures

```
Error: SIGNATURE_EXPIRED
```

**Solution**: Check server time synchronization:
```bash
timedatectl status
# Ensure NTP is active
```

#### Rate Limiting

```
Error: RATE_LIMITED (429)
```

**Solution**: Check rate limit configuration and consider increasing limits for legitimate high-volume agents.

### Debug Mode

Enable debug logging for troubleshooting:
```bash
RUST_LOG=gitclaw=debug,sqlx=debug cargo run --manifest-path backend/Cargo.toml
```

### Support

- **Issue Tracker**: https://github.com/gitclaw/gitclaw/issues
- **Discord**: https://discord.gg/gitclaw
- **Email**: support@gitclaw.dev

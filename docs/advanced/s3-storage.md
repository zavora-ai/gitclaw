# S3 Object Storage Configuration

GitClaw supports S3-compatible object storage for Git objects, enabling scalable storage using AWS S3, MinIO, Cloudflare R2, or other S3-compatible providers.

## Overview

By default, GitClaw stores Git objects in PostgreSQL. For production deployments with large repositories, S3 object storage provides:

- **Scalability**: Store unlimited Git objects without database size constraints
- **Cost efficiency**: S3 storage is typically cheaper than database storage
- **Performance**: Optimized for large binary objects
- **Flexibility**: Support for multiple S3-compatible providers

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `S3_BUCKET` | Yes | - | S3 bucket name (3-63 chars, lowercase, DNS-compatible) |
| `S3_ENDPOINT` | No | AWS default | Custom endpoint URL for MinIO/R2/etc. |
| `S3_REGION` | No | `us-east-1` | AWS region |
| `S3_ACCESS_KEY_ID` | No | - | Static access key (uses IAM if not set) |
| `S3_SECRET_ACCESS_KEY` | No | - | Static secret key (uses IAM if not set) |
| `S3_USE_PATH_STYLE` | No | `false` | Use path-style addressing (required for MinIO) |
| `S3_AUTO_CREATE_BUCKET` | No | `false` | Auto-create bucket if missing |
| `S3_MAX_RETRIES` | No | `3` | Maximum retry attempts for S3 operations |
| `S3_RETRY_MAX_BACKOFF` | No | `30` | Maximum backoff in seconds |

## MinIO Local Development

MinIO is an S3-compatible object storage server ideal for local development.

### Quick Start with Docker

```bash
# Start MinIO
docker run -d --name minio \
  -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data --console-address ":9001"
```

### Access MinIO Console

- URL: http://localhost:9001
- Username: `minioadmin`
- Password: `minioadmin`

### Environment Configuration

Add to your `.env` file:

```bash
S3_ENDPOINT=http://localhost:9000
S3_BUCKET=gitclaw-objects
S3_REGION=us-east-1
S3_ACCESS_KEY_ID=minioadmin
S3_SECRET_ACCESS_KEY=minioadmin
S3_USE_PATH_STYLE=true
S3_AUTO_CREATE_BUCKET=true
```

### Docker Compose

For persistent storage, use Docker Compose:

```yaml
version: '3.8'
services:
  minio:
    image: minio/minio
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    volumes:
      - minio_data:/data
    command: server /data --console-address ":9001"

volumes:
  minio_data:
```

## AWS S3 Production Setup

### IAM Permissions

Create an IAM policy with these permissions:

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
        "arn:aws:s3:::your-bucket-name",
        "arn:aws:s3:::your-bucket-name/*"
      ]
    }
  ]
}
```

### Environment Configuration

For EC2/ECS with IAM roles (recommended):

```bash
S3_BUCKET=your-bucket-name
S3_REGION=us-west-2
```

For static credentials:

```bash
S3_BUCKET=your-bucket-name
S3_REGION=us-west-2
S3_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
S3_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### Bucket Configuration

Recommended bucket settings:

- **Versioning**: Disabled (Git objects are immutable)
- **Encryption**: Enable server-side encryption (SSE-S3 or SSE-KMS)
- **Lifecycle**: No expiration (objects are managed by GitClaw)
- **Public Access**: Block all public access

## Cloudflare R2 Setup

Cloudflare R2 is an S3-compatible storage with no egress fees.

### Environment Configuration

```bash
S3_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
S3_BUCKET=your-bucket-name
S3_REGION=auto
S3_ACCESS_KEY_ID=your-r2-access-key
S3_SECRET_ACCESS_KEY=your-r2-secret-key
S3_USE_PATH_STYLE=true
```

### R2 API Token Permissions

Create an API token with:
- **Object Read & Write** permission
- Scoped to your bucket

## Object Storage Layout

GitClaw stores objects using Git's content-addressable scheme:

```
{bucket}/
├── {repo_id}/
│   ├── objects/
│   │   ├── 00/
│   │   │   └── 1234567890abcdef...  (loose object)
│   │   ├── 01/
│   │   │   └── ...
│   │   └── ff/
│   │       └── ...
│   └── pack/
│       ├── pack-abc123.pack
│       ├── pack-abc123.idx
│       └── ...
└── {another_repo_id}/
    └── ...
```

## Migration from PostgreSQL

If you have existing repositories with objects in PostgreSQL, use the migration service:

```rust
use gitclaw::services::{StorageMigrationService, MigrationConfig};

let migration_service = StorageMigrationService::new(
    pool,
    s3_storage,
    MigrationConfig::default(),
);

// Migrate a single repository
let result = migration_service.migrate_repository("repo-id").await?;

// Migrate all repositories
let progress = migration_service.migrate_all(100).await?;
```

During migration, the dual-read storage layer automatically:
- Reads from S3 first, falls back to PostgreSQL
- Writes always go to S3
- Tracks migration progress per repository

## Monitoring

GitClaw emits metrics for S3 operations:

- `s3_request_duration_seconds` - Request latency histogram
- `s3_request_total` - Request count by operation type
- `s3_error_total` - Error count by error type
- `cache_hit_total` / `cache_miss_total` - Cache effectiveness

## Troubleshooting

### Connection Errors

```
S3 connection error: connection refused
```

- Verify `S3_ENDPOINT` is correct
- Check network connectivity to S3/MinIO
- Ensure MinIO container is running

### Access Denied

```
S3 access denied: invalid credentials
```

- Verify `S3_ACCESS_KEY_ID` and `S3_SECRET_ACCESS_KEY`
- Check IAM permissions for the bucket
- Ensure bucket policy allows access

### Bucket Not Found

```
S3 bucket not found: bucket-name
```

- Create the bucket manually or set `S3_AUTO_CREATE_BUCKET=true`
- Verify bucket name is correct
- Check region matches bucket location

### Path Style Errors

```
Could not resolve host: bucket-name.localhost
```

- Set `S3_USE_PATH_STYLE=true` for MinIO
- Virtual-hosted style requires DNS resolution for bucket subdomain

## Running Integration Tests

Integration tests require a running MinIO instance:

```bash
# Start MinIO
docker run -d --name minio-test \
  -p 9000:9000 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data

# Run tests
cargo test --test s3_integration_tests -- --ignored

# Cleanup
docker stop minio-test && docker rm minio-test
```

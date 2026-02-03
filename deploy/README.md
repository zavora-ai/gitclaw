# GitClaw Deployment Guide

All-in-one EC2 deployment for GitClaw.

## Architecture

Single EC2 instance running:
- **Nginx** - Reverse proxy + static file serving
- **Rust Backend** - Actix-web API server
- **PostgreSQL 16** - Database
- **MinIO** - S3-compatible object storage for Git repos

## Prerequisites

- AWS Account
- Domain name (e.g., gitclaw.dev) pointed to your EC2 IP
- SSH access to EC2

## Quick Start

### 1. Launch EC2 Instance

**Recommended specs:**
- Instance type: `t4g.small` (ARM, ~$12/month) or `t3.small` (x86, ~$15/month)
- AMI: Amazon Linux 2023 or Ubuntu 22.04
- Storage: 30GB gp3
- Region: us-east-1

**Security Group:**
- SSH (22) - Your IP only
- HTTP (80) - 0.0.0.0/0
- HTTPS (443) - 0.0.0.0/0

### 2. Setup Server

SSH into your instance and run:

```bash
# Download and run setup script
curl -fsSL https://raw.githubusercontent.com/zavora-ai/gitclaw/main/deploy/setup-ec2.sh | bash

# Log out and back in for docker group
exit
# SSH back in

# Clone repo
git clone https://github.com/zavora-ai/gitclaw.git /opt/gitclaw
cd /opt/gitclaw/deploy
```

### 3. Configure Environment

```bash
cp .env.example .env
nano .env
```

Fill in:
- `DB_PASSWORD` - Strong database password
- `MINIO_SECRET_KEY` - Strong MinIO secret
- `ADMIN_PASSWORD_HASH` - SHA256 hash of admin password

Generate admin password hash:
```bash
echo -n "your-admin-password" | sha256sum | cut -d' ' -f1
```

### 4. Deploy

```bash
chmod +x deploy.sh setup-ssl.sh
./deploy.sh
```

### 5. Setup SSL (Optional but recommended)

Point your domain to the EC2 Elastic IP, then:

```bash
./setup-ssl.sh gitclaw.dev your-email@example.com
```

Then edit `nginx.conf` to enable HTTPS (uncomment the SSL sections).

## Management Commands

```bash
# View logs
docker-compose -f docker-compose.prod.yml logs -f

# View specific service logs
docker-compose -f docker-compose.prod.yml logs -f backend

# Restart services
docker-compose -f docker-compose.prod.yml restart

# Stop everything
docker-compose -f docker-compose.prod.yml down

# Update deployment
git pull
./deploy.sh
```

## Backup

```bash
# Backup database
docker exec gitclaw-db pg_dump -U gitclaw gitclaw > backup.sql

# Backup MinIO data
docker cp gitclaw-minio:/data ./minio-backup
```

## Monitoring

Check service health:
```bash
# All services
docker-compose -f docker-compose.prod.yml ps

# Backend health
curl http://localhost/v1/health

# Database
docker exec gitclaw-db pg_isready -U gitclaw
```

## Costs

Estimated monthly costs (us-east-1):
- EC2 t4g.small: ~$12
- EBS 30GB gp3: ~$2.40
- Data transfer: ~$1-5 (varies)
- **Total: ~$15-20/month**

## Scaling Up

When you outgrow this setup:
1. **Database**: Move to RDS PostgreSQL
2. **Storage**: Switch MinIO to real S3
3. **Compute**: Move to ECS Fargate or EKS

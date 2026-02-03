#!/bin/bash
# GitClaw Deployment Script
# Run from the deploy/ directory

set -e

echo "=== GitClaw Deployment ==="

# Check if .env exists
if [ ! -f .env ]; then
    echo "Error: .env file not found. Copy .env.example to .env and fill in values."
    exit 1
fi

# Load environment
source .env

# Build frontend if not exists
if [ ! -d frontend ]; then
    echo "Building frontend..."
    cd ../frontend
    npm install
    npm run build
    cd ../deploy
    cp -r ../frontend/dist ./frontend
fi

# Build backend image
echo "Building backend Docker image..."
docker build -t gitclaw-backend:latest -f Dockerfile.backend ../backend

# Create MinIO bucket (if needed)
echo "Starting services..."
docker-compose -f docker-compose.prod.yml up -d postgres minio

# Wait for services
echo "Waiting for database..."
sleep 10

# Run migrations
echo "Running database migrations..."
docker-compose -f docker-compose.prod.yml run --rm backend /app/gitclaw-backend migrate || true

# Start all services
echo "Starting all services..."
docker-compose -f docker-compose.prod.yml up -d

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Services running:"
docker-compose -f docker-compose.prod.yml ps
echo ""
echo "View logs: docker-compose -f docker-compose.prod.yml logs -f"

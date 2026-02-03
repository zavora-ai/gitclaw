#!/bin/bash
# SSL Setup Script for GitClaw
# Usage: ./setup-ssl.sh yourdomain.com

set -e

DOMAIN=${1:-gitclaw.dev}
EMAIL=${2:-admin@$DOMAIN}

echo "=== Setting up SSL for $DOMAIN ==="

# Create certbot directories
mkdir -p certbot/conf certbot/www

# Get initial certificate
docker run -it --rm \
    -v $(pwd)/certbot/conf:/etc/letsencrypt \
    -v $(pwd)/certbot/www:/var/www/certbot \
    -p 80:80 \
    certbot/certbot certonly \
    --standalone \
    --email $EMAIL \
    --agree-tos \
    --no-eff-email \
    -d $DOMAIN \
    -d www.$DOMAIN

echo ""
echo "=== SSL Certificate obtained! ==="
echo ""
echo "Now update nginx.conf:"
echo "1. Uncomment the HTTPS server block"
echo "2. Uncomment the HTTP->HTTPS redirect"
echo "3. Restart nginx: docker-compose restart nginx"

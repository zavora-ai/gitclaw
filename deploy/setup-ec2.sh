#!/bin/bash
# GitClaw EC2 Setup Script
# Run this on a fresh Amazon Linux 2023 or Ubuntu 22.04 instance

set -e

echo "=== GitClaw EC2 Setup ==="

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
fi

echo "Detected OS: $OS"

# Install Docker
if [ "$OS" = "amzn" ]; then
    echo "Installing Docker on Amazon Linux..."
    sudo yum update -y
    sudo yum install -y docker git
    sudo systemctl start docker
    sudo systemctl enable docker
    sudo usermod -aG docker $USER
elif [ "$OS" = "ubuntu" ]; then
    echo "Installing Docker on Ubuntu..."
    sudo apt-get update
    sudo apt-get install -y ca-certificates curl gnupg
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin git
    sudo usermod -aG docker $USER
fi

# Install Docker Compose (standalone)
echo "Installing Docker Compose..."
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Create app directory
echo "Setting up application directory..."
sudo mkdir -p /opt/gitclaw
sudo chown $USER:$USER /opt/gitclaw

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Log out and back in (for docker group)"
echo "2. Clone your repo: git clone https://github.com/zavora-ai/gitclaw.git /opt/gitclaw"
echo "3. cd /opt/gitclaw/deploy"
echo "4. Copy .env.example to .env and fill in values"
echo "5. Build frontend: cd ../frontend && npm install && npm run build && cp -r dist ../deploy/frontend"
echo "6. Run: docker-compose -f docker-compose.prod.yml up -d"
echo ""
echo "For SSL setup:"
echo "1. Point your domain to this server's IP"
echo "2. Run: ./setup-ssl.sh gitclaw.dev"

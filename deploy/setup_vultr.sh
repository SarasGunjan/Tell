#!/usr/bin/env bash
# ==============================================================================
# Tell Platform - Automated Vultr Cloud Compute Provisioning Script
# Operating System: Ubuntu 22.04 LTS / 24.04 LTS on Vultr
# ==============================================================================

set -euo pipefail

echo "=========================================================="
echo "🛡️  Provisioning Tell Platform on Vultr Cloud Compute"
echo "=========================================================="

# 1. Update OS Packages
echo "--> [1/6] Updating Ubuntu packages..."
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y && sudo apt-get upgrade -y
sudo apt-get install -y git curl wget ufw nginx certbot python3-certbot-nginx apt-transport-https ca-certificates gnupg lsb-release

# 2. Install Docker & Docker Compose
echo "--> [2/6] Installing Docker Engine..."
if ! command -v docker &> /dev/null; then
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -y
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    sudo systemctl enable docker
    sudo systemctl start docker
    sudo usermod -aG docker "$USER"
fi

# 3. Configure Firewall (UFW)
echo "--> [3/6] Configuring UFW Firewall..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# 4. Clone / Deploy Tell Repository
echo "--> [4/6] Setting up Tell Platform Directory..."
DEPLOY_DIR="/opt/tell"
sudo mkdir -p "$DEPLOY_DIR"
sudo chown -R "$USER":"$USER" "$DEPLOY_DIR"

if [ -f .env.example ] && [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env template. Populate with API keys before starting."
fi

# 5. Configure Nginx Reverse Proxy
echo "--> [5/6] Configuring Nginx..."
sudo cp deploy/nginx.conf /etc/nginx/sites-available/tell
sudo ln -sf /etc/nginx/sites-available/tell /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx

# 6. Launch Application with Docker Compose
echo "--> [6/6] Launching Tell Container..."
cd deploy
docker compose down || true
docker compose up -d --build

echo "=========================================================="
echo "✅ Tell Platform Successfully Deployed on Vultr!"
echo "Access the dashboard at: http://$(curl -s ifconfig.me)"
echo "To attach an SSL domain run: sudo certbot --nginx -d yourdomain.com"
echo "=========================================================="

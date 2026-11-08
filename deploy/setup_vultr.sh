#!/usr/bin/env bash
# Tell web platform - Vultr provisioning (Ubuntu 22.04 / 24.04). Idempotent; run as root.
#   REPO_URL, BRANCH, DEPLOY_DIR, DOMAIN, EMAIL can be overridden via environment.
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/SarasGunjan/Tell.git}"
BRANCH="${BRANCH:-feature/web-frontend}"
DEPLOY_DIR="${DEPLOY_DIR:-/opt/tell}"
EMAIL="${EMAIL:-}"
DOMAIN="${DOMAIN:-}"

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"
export DEBIAN_FRONTEND=noninteractive

log() { echo "--> $*"; }

log "[1/8] Installing packages"
$SUDO apt-get update -y
$SUDO apt-get install -y git curl ufw nginx certbot python3-certbot-nginx ca-certificates gnupg

log "[2/8] Docker"
if ! command -v docker >/dev/null 2>&1; then
    . /etc/os-release
    $SUDO install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | $SUDO gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
        | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
    $SUDO apt-get update -y
    $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
$SUDO systemctl enable --now docker

log "[3/8] Firewall"
$SUDO ufw allow OpenSSH
$SUDO ufw allow 80/tcp
$SUDO ufw allow 443/tcp
$SUDO ufw --force enable

log "[4/8] Repository ($BRANCH) in $DEPLOY_DIR"
if [ -d "$DEPLOY_DIR/.git" ]; then
    git -C "$DEPLOY_DIR" fetch origin "$BRANCH"
    git -C "$DEPLOY_DIR" checkout "$BRANCH"
    git -C "$DEPLOY_DIR" pull --ff-only origin "$BRANCH"
else
    $SUDO mkdir -p "$DEPLOY_DIR"
    $SUDO git clone --branch "$BRANCH" "$REPO_URL" "$DEPLOY_DIR"
fi

log "[5/8] Environment"
cd "$DEPLOY_DIR"
if [ ! -f .env ]; then
    cp .env.example .env
    chmod 600 .env
    echo "Created $DEPLOY_DIR/.env from .env.example."
fi
if ! grep -Eq '^GEMINI_API_KEY=.+' .env || grep -Eq '^GEMINI_API_KEY=your_' .env; then
    echo "WARNING: GEMINI_API_KEY is not set in $DEPLOY_DIR/.env. AI features run in offline mode until keys are set."
    echo "         Edit the file, then: cd $DEPLOY_DIR && docker compose -f deploy/docker-compose.yml up -d"
fi
mkdir -p data results

log "[6/8] Nginx"
if [ -z "$DOMAIN" ]; then
    IP="$(curl -4fsS --max-time 10 https://ifconfig.me || true)"
    if ! [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "ERROR: could not detect public IPv4. Re-run with DOMAIN=your.domain" >&2
        exit 1
    fi
    DOMAIN="${IP//./-}.sslip.io"
fi
$SUDO cp deploy/nginx.conf /etc/nginx/sites-available/tell
$SUDO sed -i "s/server_name _;/server_name ${DOMAIN};/" /etc/nginx/sites-available/tell
$SUDO ln -sf /etc/nginx/sites-available/tell /etc/nginx/sites-enabled/tell
$SUDO rm -f /etc/nginx/sites-enabled/default
$SUDO nginx -t
$SUDO systemctl enable nginx
$SUDO systemctl reload nginx || $SUDO systemctl restart nginx

log "[7/8] Building and starting the container"
$SUDO docker compose -f deploy/docker-compose.yml up -d --build

log "Waiting for health"
ok=0
for _ in $(seq 1 30); do
    if curl -fsS --max-time 3 http://127.0.0.1:8000/api/status >/dev/null 2>&1; then ok=1; break; fi
    sleep 2
done
if [ "$ok" -ne 1 ]; then
    echo "ERROR: app not healthy after 60s. Check: docker compose -f deploy/docker-compose.yml logs tell" >&2
    exit 1
fi

log "[8/8] HTTPS (certbot)"
SCHEME="http"
CB_EMAIL=(--register-unsafely-without-email)
[ -z "$EMAIL" ] || CB_EMAIL=(--email "$EMAIL")
if $SUDO certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --redirect "${CB_EMAIL[@]}"; then
    SCHEME="https"
else
    echo "WARNING: certbot failed; site is still served over http. Retry later: certbot --nginx -d $DOMAIN"
fi

echo "=========================================================="
echo "Tell is live: ${SCHEME}://${DOMAIN}"
echo "=========================================================="

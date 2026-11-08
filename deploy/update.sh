#!/usr/bin/env bash
# Pull latest code and rebuild. Run on the server. (DEPLOY_DIR defaults to /opt/tell)
# New CSVs dropped into $DEPLOY_DIR/results need NO rebuild: they hot-reload on the next request.
set -euo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-/opt/tell}"
BRANCH="${BRANCH:-feature/web-frontend}"
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"

cd "$DEPLOY_DIR"
git fetch origin "$BRANCH"
git checkout "$BRANCH"
git pull --ff-only origin "$BRANCH"
$SUDO docker compose -f deploy/docker-compose.yml up -d --build
$SUDO docker image prune -f >/dev/null
echo "Updated. Status: curl -s http://127.0.0.1:8000/api/status"

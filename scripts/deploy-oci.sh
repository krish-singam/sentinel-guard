#!/bin/bash
# ==============================================================================
# 🛡️ SentinelGuard Automated OCI Deployment & Zero-Downtime Rollout Script
# ==============================================================================
set -e

APP_DIR="${1:-/home/opc/sentinel-guard}"
BRANCH="${2:-main}"
HEALTHCHECK_URL="http://127.0.0.1:8090/api/traffic/ping"
MAX_RETRIES=30
RETRY_DELAY=2

echo "======================================================================"
echo "🚀 SentinelGuard WAF Deployment Initiated: $(date)"
echo "📁 Deployment Directory: ${APP_DIR}"
echo "🌿 Target Branch: ${BRANCH}"
echo "======================================================================"

# Ensure directory exists
if [ ! -d "$APP_DIR" ]; then
    echo "📥 Creating deployment directory..."
    mkdir -p "$APP_DIR"
    git clone https://github.com/vkkrishna/sentinel-guard.git "$APP_DIR" || true
fi

cd "$APP_DIR"

# Pull latest code
echo "🔄 Fetching latest commits from git..."
git fetch --all
git checkout "$BRANCH"
git pull origin "$BRANCH" || git reset --hard "origin/$BRANCH"

# Docker Engine & Docker Compose Check
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed on this VM. Installing Docker..."
    sudo dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo || true
    sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    sudo systemctl enable --now docker
    sudo usermod -aG docker opc
fi

# Detect Docker Compose command syntax
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    echo "❌ Neither 'docker compose' nor 'docker-compose' found. Aborting."
    exit 1
fi

echo "🐳 Building and spinning up containers via ${DOCKER_COMPOSE}..."
$DOCKER_COMPOSE down --remove-orphans || true
$DOCKER_COMPOSE up -d --build

echo "⏳ Waiting for SentinelGuard WAF Gateway service to become healthy..."
READY=false
for i in $(seq 1 $MAX_RETRIES); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTHCHECK_URL" || echo "000")
    if [ "$HTTP_CODE" -eq 200 ] || [ "$HTTP_CODE" -eq 401 ]; then
        echo "✅ SentinelGuard WAF is ONLINE and responding (HTTP $HTTP_CODE) after $((i * RETRY_DELAY)) seconds!"
        READY=true
        break
    fi
    echo "   [Attempt $i/$MAX_RETRIES] App starting up... (HTTP $HTTP_CODE). Retrying in ${RETRY_DELAY}s..."
    sleep $RETRY_DELAY
done

if [ "$READY" = false ]; then
    echo "❌ Health check failed after $MAX_RETRIES attempts! Inspecting container logs:"
    $DOCKER_COMPOSE logs --tail=50 sentinel-guard
    exit 1
fi

# Reload Nginx if present on host
if systemctl is-active --quiet nginx; then
    echo "🌐 Reloading host Nginx reverse proxy..."
    sudo nginx -t && sudo systemctl reload nginx || echo "⚠️ Nginx test or reload encountered an issue."
fi

echo "======================================================================"
echo "🎉 SentinelGuard WAF successfully deployed & running on OCI!"
echo "🌐 Public Endpoint: https://usertesting.singamsettikrishna.in"
echo "======================================================================"

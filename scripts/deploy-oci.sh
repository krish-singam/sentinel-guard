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

# Install / refresh host Nginx so any Host whose A record points here hits the WAF.
# Git pull alone is not enough: nginx reads /etc/nginx, not the git working tree.
if command -v nginx >/dev/null 2>&1; then
    echo "🌐 Installing nginx/sentinelguard.conf onto the host..."
    NGINX_SRC="${APP_DIR}/nginx/sentinelguard.conf"
    NGINX_DST="/etc/nginx/conf.d/sentinelguard.conf"
    if [ -f "$NGINX_SRC" ]; then
        sudo cp "$NGINX_SRC" "$NGINX_DST"

        # Old vhosts that send usertesting straight to :8080 (or a stale :8090 file) bypass/conflict with the WAF catch-all.
        for f in \
            /etc/nginx/conf.d/usertesting.conf \
            /etc/nginx/conf.d/usertesting.singamsettikrishna.in.conf \
            /etc/nginx/sites-enabled/usertesting.singamsettikrishna.in \
            /etc/nginx/sites-enabled/usertesting.conf
        do
            if [ -e "$f" ]; then
                echo "   Disabling conflicting vhost: $f"
                sudo mv "$f" "${f}.disabled.$(date +%Y%m%d%H%M%S)" || true
            fi
        done

        if sudo nginx -t; then
            sudo systemctl reload nginx
            echo "✅ Nginx installed ${NGINX_DST} and reloaded."
        else
            echo "❌ nginx -t failed. Common cause: missing TLS certs referenced in sentinelguard.conf"
            echo "   HTTP catch-all still needs a valid conf. Check:"
            echo "     ls /etc/letsencrypt/live/"
            echo "   If only usertesting certs exist, either:"
            echo "     sudo certbot --nginx -d sentinel-guard.singamsettikrishna.in"
            echo "   or temporarily comment the listen 443 blocks, then: sudo nginx -t && sudo systemctl reload nginx"
            exit 1
        fi
    else
        echo "⚠️ ${NGINX_SRC} not found in the repo checkout. Skipping nginx install."
    fi
else
    echo "⚠️ nginx is not installed on this VM. App is on :8090 only until you install nginx."
fi

echo "======================================================================"
echo "🎉 SentinelGuard WAF successfully deployed & running on OCI!"
echo "🌐 Public Endpoint: https://usertesting.singamsettikrishna.in"
echo "======================================================================"

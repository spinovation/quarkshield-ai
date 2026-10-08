#!/usr/bin/env bash
# ==============================================================================
# QuarkShield Desktop & Host PQC Vulnerability Scanner - Standalone Deployment
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo " 🛡️ Deploying QuarkShield Desktop & Host PQC Scanner (Standalone VPS)"
echo "======================================================================"

# Ensure Docker is installed and running
if ! command -v docker >/dev/null 2>&1; then
  echo "❌ Error: Docker is not installed. Please install docker before proceeding."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "❌ Error: 'docker compose' plugin is not available."
  exit 1
fi

# Prepare environment file if missing. SECURITY: never boot on the committed
# .env.example placeholders — they contain a PUBLIC JWT secret and a known bootstrap
# password. Generate strong random secrets, then refuse to start if any remain a
# placeholder so the server never runs on a forgeable session secret.
if [ ! -f .env ]; then
  echo "ℹ️ No .env found — creating one from .env.example with freshly generated secrets..."
  cp .env.example .env
  GEN_JWT="$(openssl rand -hex 32)"
  GEN_LIC="$(openssl rand -hex 32)"
  GEN_CBOM="$(openssl rand -hex 32)"
  # Replace the template secret lines with generated random values (portable sed).
  sed -i.bak \
    -e "s|^JWT_SECRET=.*|JWT_SECRET=${GEN_JWT}|" \
    -e "s|^LICENSE_SIGNING_SECRET=.*|LICENSE_SIGNING_SECRET=${GEN_LIC}|" \
    -e "s|^CBOM_SIGNING_SECRET=.*|CBOM_SIGNING_SECRET=${GEN_CBOM}|" \
    .env && rm -f .env.bak
  echo "   ✓ Generated JWT_SECRET / LICENSE_SIGNING_SECRET / CBOM_SIGNING_SECRET."
  echo "   ⚠️  Set a strong BOOTSTRAP_ADMIN_PASSWORD in .env before first login (still a placeholder)."
fi

# Fail closed: refuse to deploy if any critical secret is still a placeholder/too short.
if grep -qiE '^(JWT_SECRET|LICENSE_SIGNING_SECRET)=.*(replace-with|change[-_]?me|changeme|example|placeholder|your[-_])' .env; then
  echo "❌ Refusing to deploy: .env still contains placeholder secrets. Set strong random JWT_SECRET / LICENSE_SIGNING_SECRET." >&2
  exit 1
fi
if grep -qiE '^BOOTSTRAP_ADMIN_PASSWORD=.*(replace-with|change[-_]?me|changeme|example|placeholder|your[-_])' .env; then
  echo "❌ Refusing to deploy: BOOTSTRAP_ADMIN_PASSWORD is still a placeholder. Set a strong unique password (or remove the line)." >&2
  exit 1
fi

echo "📦 Step 1: Building production containers..."
docker compose build --no-cache

echo "🚀 Step 2: Launching Postgres database and Management Console..."
docker compose up -d --force-recreate

echo "⏳ Step 3: Verifying service health..."
MAX_RETRIES=20
COUNT=0
HEALTHY=false

while [ $COUNT -lt $MAX_RETRIES ]; do
  if curl -s http://localhost:5050/health | grep -q '"status":"ok"'; then
    HEALTHY=true
    break
  fi
  echo "   Waiting for API to initialize... ($((COUNT+1))/$MAX_RETRIES)"
  sleep 2
  COUNT=$((COUNT+1))
done

if [ "$HEALTHY" = true ]; then
  echo "======================================================================"
  echo "✅ Deployment Successful!"
  echo "🌐 Management Console: http://localhost:5050 (or your VPS IP / domain)"
  echo "📥 Agent Downloads:     http://localhost:5050/downloads/"
  echo "📡 Health Endpoint:     http://localhost:5050/health"
  echo "📜 1-Click Installer:   http://localhost:5050/api/scan/agent/install.sh"
  echo "======================================================================"
else
  echo "⚠️ Warning: Container launched but healthcheck timed out. Inspect logs with:"
  echo "   docker compose logs -f scanner-console"
fi

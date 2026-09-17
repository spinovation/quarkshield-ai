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

# Prepare environment file if missing
if [ ! -f .env ]; then
  echo "ℹ️ Creating default .env from .env.example..."
  cp .env.example .env
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

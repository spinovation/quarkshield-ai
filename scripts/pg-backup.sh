#!/usr/bin/env bash
# Nightly PostgreSQL backup for the QuarkShield central plane.
# Dumps the pqc-scanner-db container's database to a gzip file with rotation.
# Install as a 2 AM cron (see scripts/README-backup.md).
set -euo pipefail

BACKUP_DIR="${QS_BACKUP_DIR:-/opt/backups/quarkshield}"
RETAIN_DAYS="${QS_BACKUP_RETAIN_DAYS:-14}"
CONTAINER="${QS_DB_CONTAINER:-pqc-scanner-db}"

mkdir -p "$BACKUP_DIR"
ts="$(date +%Y%m%d-%H%M%S)"
out="$BACKUP_DIR/quarkshield_${ts}.sql.gz"

# Use the container's own env for user/db so we never hardcode credentials.
if docker exec "$CONTAINER" sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' | gzip > "$out"; then
  # Guard against a truncated/empty dump (a broken backup is worse than none).
  size=$(stat -c '%s' "$out" 2>/dev/null || echo 0)
  if [ "$size" -lt 1000 ]; then
    echo "$(date -Is) ERROR: dump looks empty ($size bytes) — removing $out" >&2
    rm -f "$out"
    exit 1
  fi
  # Rotate: delete dumps older than the retention window.
  find "$BACKUP_DIR" -name 'quarkshield_*.sql.gz' -type f -mtime "+${RETAIN_DAYS}" -delete
  echo "$(date -Is) OK backup -> $out ($(du -h "$out" | cut -f1)); retained ${RETAIN_DAYS}d"
else
  echo "$(date -Is) ERROR: pg_dump failed" >&2
  rm -f "$out"
  exit 1
fi

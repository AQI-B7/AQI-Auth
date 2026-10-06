#!/usr/bin/env bash
# Deploy pending Prisma migrations to $DATABASE_URL, taking a pg_dump
# snapshot first so `scripts/rollback.sh` has something to restore from.
#
# Usage: ./scripts/migrate.sh
# Env:   DATABASE_URL (required), BACKUP_DIR (optional, default ./backups)

set -euo pipefail

if [ -z "${DATABASE_URL:-}" ]; then
  echo "DATABASE_URL is not set" >&2
  exit 1
fi

BACKUP_DIR="${BACKUP_DIR:-./backups}"
mkdir -p "$BACKUP_DIR"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SNAPSHOT_PATH="$BACKUP_DIR/pre-migrate-$TIMESTAMP.dump"

echo "==> Snapshotting database to $SNAPSHOT_PATH"
pg_dump --format=custom --file="$SNAPSHOT_PATH" "$DATABASE_URL"

echo "==> Recording snapshot as the rollback target"
echo "$SNAPSHOT_PATH" > "$BACKUP_DIR/LATEST"

echo "==> Applying pending migrations"
npx prisma migrate deploy

echo "==> Done. To roll back this deploy: ./scripts/rollback.sh"

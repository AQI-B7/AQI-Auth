#!/usr/bin/env bash
# Restore the database from the most recent snapshot taken by
# scripts/migrate.sh. This is a full-database restore (the only rollback
# strategy that's actually reliable with Prisma, which has no native
# down-migrations) — not a per-migration undo. See MIGRATIONS.md.
#
# Usage: ./scripts/rollback.sh [snapshot-file]
# Env:   DATABASE_URL (required), BACKUP_DIR (optional, default ./backups)

set -euo pipefail

if [ -z "${DATABASE_URL:-}" ]; then
  echo "DATABASE_URL is not set" >&2
  exit 1
fi

BACKUP_DIR="${BACKUP_DIR:-./backups}"
SNAPSHOT_PATH="${1:-}"

if [ -z "$SNAPSHOT_PATH" ]; then
  if [ ! -f "$BACKUP_DIR/LATEST" ]; then
    echo "No snapshot file given and no $BACKUP_DIR/LATEST pointer found." >&2
    echo "Usage: ./scripts/rollback.sh path/to/snapshot.dump" >&2
    exit 1
  fi
  SNAPSHOT_PATH="$(cat "$BACKUP_DIR/LATEST")"
fi

if [ ! -f "$SNAPSHOT_PATH" ]; then
  echo "Snapshot not found: $SNAPSHOT_PATH" >&2
  exit 1
fi

echo "!! This will DROP and recreate every table in the target database"
echo "!! Target: $DATABASE_URL"
echo "!! Snapshot: $SNAPSHOT_PATH"
read -r -p "Type 'restore' to continue: " CONFIRM
if [ "$CONFIRM" != "restore" ]; then
  echo "Aborted."
  exit 1
fi

echo "==> Restoring $SNAPSHOT_PATH"
pg_restore --clean --if-exists --no-owner --dbname="$DATABASE_URL" "$SNAPSHOT_PATH"

echo "==> Restore complete. Verify _prisma_migrations reflects the restored state:"
echo "    npx prisma migrate status"

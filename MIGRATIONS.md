# Migration & Rollback Strategy

Prisma Migrate has **no native "down" migration** — every generated
migration is forward-only SQL. That's a real limitation, so this project
uses two complementary strategies instead of pretending otherwise:

## 1. Expand/contract for anything destructive

Never ship a migration that both adds and removes something in the same
step if it touches production data. Split it across two (or three)
deploys:

1. **Expand** — add the new column/table/index as *nullable* or with a
   safe default. Old code keeps working unmodified.
2. **Migrate + dual-write** — deploy application code that writes to
   both the old and new shape; backfill existing rows.
3. **Contract** — once the new shape has been live and verified (a full
   deploy cycle later, not the same PR), drop the old column/table in a
   *separate* migration.

This means at any point you can roll back the **application code** by
one deploy without needing a database rollback at all — the schema from
two steps ago is still compatible with the code from two steps ago.
This is the primary rollback mechanism for this project; the pg_dump
snapshot below is the fallback for when that's not possible (e.g. a
migration that turns out to be wrong before step 3 ever ships).

## 2. Snapshot-based rollback for everything else

For migrations that don't fit the expand/contract pattern (new project,
early-stage schema changes, a fixable mistake caught immediately after
deploy), `scripts/migrate.sh` takes a `pg_dump --format=custom` snapshot
of the *entire* database immediately before running
`prisma migrate deploy`, and records its path in `backups/LATEST`.

```bash
# Deploy (snapshots first, automatically)
DATABASE_URL=postgresql://... ./scripts/migrate.sh

# Roll back to the pre-deploy snapshot if something's wrong
DATABASE_URL=postgresql://... ./scripts/rollback.sh
```

**This is a full-database restore, not a selective undo.** Any writes
that happened between the deploy and the rollback are lost. That's an
acceptable trade-off for catching a bad migration within minutes of
deploying it; it is not a substitute for point-in-time recovery on your
Postgres provider (RDS/Cloud SQL/etc. — enable that separately for
real disaster recovery).

## Recommended CI/CD flow

```
1. PR opens a migration           → prisma migrate dev locally, commit the
                                     generated SQL under prisma/migrations/
2. CI                             → prisma migrate diff --from-migrations
                                     --to-schema-datamodel to confirm the
                                     committed SQL matches schema.prisma
                                     (catches hand-edited migration files)
3. Merge to main                  → scripts/migrate.sh runs against staging
4. Verify staging                 → smoke tests / manual check
5. scripts/migrate.sh             → production, same snapshot-then-deploy flow
```

## If you need a true per-migration "down" script

For any migration you know in advance is risky enough to want an exact
inverse (not just a full restore), write it by hand next to the
generated one:

```
prisma/migrations/20260115120000_add_webhook_delivery/
  migration.sql       # generated "up"
  down.sql             # hand-written "down" — not run automatically;
                        # apply manually with `psql $DATABASE_URL -f down.sql`
                        # BEFORE re-running migrate.sh, if you need to
                        # unwind just this one change instead of a full
                        # snapshot restore.
```

Prisma doesn't execute `down.sql` itself — it's a convention, not a
built-in feature — but keeping it next to the migration it undoes means
whoever's on call at 3am isn't improvising a rollback under pressure.

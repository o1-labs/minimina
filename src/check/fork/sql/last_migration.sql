-- The last schema migration of the archive (written by upgrade.sql).
SELECT protocol_version, migration_version, status::text
FROM migration_history
ORDER BY commit_start_at DESC
LIMIT 1

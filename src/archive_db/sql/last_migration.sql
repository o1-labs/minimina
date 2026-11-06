SELECT protocol_version, migration_version, status::text AS status
FROM migration_history
ORDER BY commit_start_at DESC
LIMIT 1

SELECT max(pv.transaction) AS transaction
FROM blocks b
JOIN protocol_versions pv ON pv.id = b.protocol_version_id
WHERE b.global_slot_since_genesis < $1

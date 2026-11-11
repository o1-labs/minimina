-- The chain from the highest block at or after global slot $1 (the postfork
-- genesis slot) down to the first block, following parent_id.
WITH RECURSIVE chain AS (
    (SELECT id, parent_id, height, state_hash, parent_hash, chain_status,
            global_slot_since_genesis, global_slot_since_hard_fork
     FROM blocks
     WHERE global_slot_since_genesis >= $1
     ORDER BY height DESC, id
     LIMIT 1)
    UNION ALL
    SELECT b.id, b.parent_id, b.height, b.state_hash, b.parent_hash, b.chain_status,
           b.global_slot_since_genesis, b.global_slot_since_hard_fork
    FROM blocks b
    JOIN chain c ON b.id = c.parent_id
)
SELECT id, parent_id, height, state_hash, parent_hash, chain_status::text AS chain_status,
       global_slot_since_genesis, global_slot_since_hard_fork
FROM chain
ORDER BY height DESC

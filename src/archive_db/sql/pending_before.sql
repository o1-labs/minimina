-- The blocks before global slot $1 (the postfork genesis slot) that are
-- still pending: once the fork is settled, every prefork block is canonical
-- or orphaned.
SELECT id, parent_id, height, state_hash, parent_hash, chain_status::text AS chain_status,
       global_slot_since_genesis, global_slot_since_hard_fork
FROM blocks
WHERE global_slot_since_genesis < $1 AND chain_status = 'pending'
ORDER BY height

SELECT state_hash, height, global_slot_since_genesis
FROM blocks
WHERE global_slot_since_genesis = $1
  AND global_slot_since_hard_fork = 0

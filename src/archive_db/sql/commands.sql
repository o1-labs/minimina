-- The archived blocks that hold the user commands with hashes $1.
SELECT uc.hash, uc.nonce, pk.value AS fee_payer, b.state_hash AS block_state_hash,
       b.height, buc.status::text AS status
FROM user_commands uc
JOIN public_keys pk ON pk.id = uc.fee_payer_id
JOIN blocks_user_commands buc ON buc.user_command_id = uc.id
JOIN blocks b ON b.id = buc.block_id
WHERE uc.hash = ANY($1)

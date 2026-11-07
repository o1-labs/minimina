-- The MINA accounts the archive recorded for the block with state hash $1
-- (the postfork genesis: every account of the fork ledger). Token $2.
SELECT pk.value, aa.balance, aa.nonce, aa.receipt_chain_hash, dpk.value,
       ti.initial_minimum_balance, ti.cliff_time, ti.cliff_amount,
       ti.vesting_period, ti.vesting_increment
FROM blocks b
JOIN accounts_accessed aa ON aa.block_id = b.id
JOIN account_identifiers ai ON ai.id = aa.account_identifier_id
JOIN public_keys pk ON pk.id = ai.public_key_id
JOIN tokens t ON t.id = ai.token_id
LEFT JOIN public_keys dpk ON dpk.id = aa.delegate_id
LEFT JOIN timing_info ti ON ti.id = aa.timing_id
WHERE b.state_hash = $1 AND t.value = $2

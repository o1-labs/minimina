-- The MINA accounts of the genesis ledger the archive recorded in
-- genesis_accounts for the genesis block at height $1 (with
-- --hardfork-handover: the fork ledger). Token $2. genesis_accounts holds
-- no receipt chain hash or delegate.
SELECT ga.public_key, ga.balance, ga.nonce, NULL::text AS receipt_chain_hash,
       NULL::text AS delegate, ga.initial_minimum_balance, ga.cliff_time,
       ga.cliff_amount, ga.vesting_period, ga.vesting_increment
FROM genesis_accounts ga
WHERE ga.genesis_height = $1 AND ga.token = $2

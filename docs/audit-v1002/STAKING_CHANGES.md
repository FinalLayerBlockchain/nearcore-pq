# Final Layer v1002 — Staking System Changes
Generated: 2026-04-04T21:15:56.124698

## 1. Validator Fee System
validator_claim_fee_bps: king.fl=0, validator-1.fl=500 (5%), validator-2.fl=300 (3%)
validator_deposit_fee_bps: king.fl=0, validator-1.fl=5 (0.05%), validator-2.fl=3 (0.03%)

## 2. Three Staking Modes
Stake:   new_total = locked + stakeAmount
Claim:   new_total = locked - claimAmount (timer resets)
Unstake: new_total = locked - unstakeAmount (0=full; timer resets on partial)

## 3. Validator Roles
Block Producer: num_expected_blocks > 0
Chunk Producer: num_expected_blocks=0 and chunks > 0
Endorser: both 0 (active)

## 4. APY Schedule (FL v1002)
Year 0 (epochs 0-729):    20%
Year 1 (epochs 730-1459):  5%
Year 2+ (epochs 1460+):    1% floor

## 5. Genesis Stake
king.fl: 300M staked, 700M liquid
validator-1.fl: 100M staked, claim=5%, deposit=0.05%
validator-2.fl: 100M staked, claim=3%, deposit=0.03%

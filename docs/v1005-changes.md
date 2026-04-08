# Final Layer v1005 Protocol Changes

## Overview

Protocol version **1005** introduces the **send-to-activate** account creation flow,
allowing any existing account to create a direct `.fl` sub-account by including an
`AddKey` action with a `CreateAccount` action in a single transaction batch.

## Changes

### 1. Permissionless `.fl` Account Creation (`runtime/runtime/src/actions.rs`)

**Previous behavior (v1004):**  
Sub-account creation required the predecessor account to be the parent account.
For example, `jack.fl` could only be created by the `fl` registrar account — which
does not exist on Final Layer's chain.

**New behavior (v1005):**  
Any account may create a direct `.fl` account (one level deep only). The check is:
- `account_id` must end with `.fl`
- `account_id` must have exactly one `.` (e.g. `jack.fl`, not `deep.jack.fl`)

This allows the **send-to-activate** wallet flow: a user can fund a new `.fl`
account by creating it with a `CreateAccount + AddKey + Transfer` action batch,
activated in a single transaction from any sender.

Multi-level `.fl` sub-accounts (e.g. `deep.jack.fl`) still require `jack.fl`
as the predecessor.

### 2. Protocol Version Bump (`core/primitives-core/src/version.rs`)

`STABLE_PROTOCOL_VERSION` updated from `1004` to `1005`.

### 3. Wallet UI Improvements

- **Send page:** The send flow detects when a recipient does not exist on-chain
  and shows a "Send to Activate" modal that collects the recipient's public key.
  The wallet then issues a `create-account` command instead of a plain `transfer`.
- **Transaction display:** Gas fee shown to 9 decimal places and in USD equivalent.
- **FNDSA badge:** Algorithm label displayed inline in the gas fee row.

## Epoch Config

A fresh genesis requires `epoch_configs/1005.json` in the node home directory.
This file configures the 9-shard layout using V1 shard layout with boundary
accounts: `ccc`, `fff`, `iii`, `lll`, `ooo`, `rrr`, `uuu`, `xxx`.

## Backward Compatibility

Accounts created under the old rules (v1004 or earlier) are unaffected.
The new permissive `.fl` creation rule only affects the **predecessor check**
for new sub-account creation transactions.

## Chain Reset

A clean genesis restart was performed to activate v1005 from block 0.
All genesis accounts received fresh FNDSA (Falcon-512) keys.

| Account | Role |
|---------|------|
| `king.fl` | Primary validator, faucet, treasury |
| `validator-1.fl` | Secondary validator |
| `validator-2.fl` | Tertiary validator |
| `alpha.fl` – `epsilon.fl` | Genesis token holders |

# percolator-match

> **⚠️ DISCLAIMER: FOR EDUCATIONAL PURPOSES ONLY**
>
> This code has **NOT been audited**. Do NOT use in production or with real funds. This is experimental software provided for learning and testing purposes only. Use at your own risk.

Passive LP matcher for [Percolator](https://github.com/aeyakovenko/percolator-prog).

## Overview

A Solana program that provides passive market making by quoting ±50 basis points off the oracle price. Called via CPI from Percolator's `TradeCpi` instruction.

## Features

- **Passive quoting**: Bid/ask spread of 50 bps (0.5%) around oracle price
- **Integer-only math**: Deterministic, no floating point
- **Rounding**: Bid rounds down, ask rounds up (both passive-favorable)
- **LP PDA binding**: Context account stores expected LP PDA, verified on each call
- **ABI compatible**: Implements Percolator's matcher context account interface

## Quote Calculation

```
bid = floor(oracle_price × 9950 / 10000)
ask = ceil(oracle_price × 10050 / 10000)
```

Example with oracle price of 100,000:
- Bid: 99,500
- Ask: 100,500

### vAMM impact

The vAMM kind adds impact on top of spread and fee. Impact is priced along the LP's
per-asset inventory, not per request: marginal impact at LP exposure `e` is
`min(cap, 2 × impact_k_bps × notional(e) / liquidity_notional_e6)`, and a fill pays the
average of that curve over the exposure it adds. A fill from a flat book pays
`impact_k_bps × notional(fill) / liquidity_notional_e6`, as before, but splitting an order
walks the same curve and cannot be cheaper than the aggregate (rounding always goes against
the taker). The portion of a fill that reduces existing LP exposure pays no impact.

### Inventory

Inventory is tracked per asset (up to 6 assets with nonzero inventory at once; a slot frees
when its asset returns to flat). `max_inventory_abs` caps each asset separately, all
arithmetic is checked, and a fill in a seventh asset gets a zero fill.

## Building

```bash
# Build for Solana
cargo-build-sbf

# Run tests
cargo test
```

## Deployment

The compiled program is output to `target/deploy/percolator_match.so`.

### Setup

1. Deploy the matcher program
2. Create a context account owned by the matcher program (minimum 96 bytes, recommended 320 bytes)
3. Initialize the context with the LP PDA (Tag 2 instruction)
4. Register the LP with Percolator via `InitLP`, setting:
   - `matcher_program`: This program's deployed address
   - `matcher_context`: The initialized context account

## Context Account Layout

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0-63 | return | 64 | Matcher return data (written on each call) - ABI required |
| 64-319 | matcher state | 256 | Configuration, stored LP PDA, per-asset inventory |

Minimum size: 320 bytes.

## Instructions

### Tag 0: Matcher Call (from Percolator CPI)

Executes passive matching logic. Requires LP PDA to be a signer and match the stored PDA.

#### Accounts

| Index | Name | Type | Description |
|-------|------|------|-------------|
| 0 | lp_pda | Signer | LP PDA (must match stored PDA) |
| 1 | matcher_ctx | Writable | Context account owned by this program |

#### Instruction Data (67 bytes)

| Offset | Field | Type | Description |
|--------|-------|------|-------------|
| 0 | tag | u8 | Always 0 |
| 1-9 | req_id | u64 | Request ID (echoed) |
| 9-11 | asset_index | u16 | Market asset index, echoed in the response |
| 11-19 | lp_account_id | u64 | LP account ID (echoed) |
| 19-27 | oracle_price_e6 | u64 | Oracle price (1e6 scaled) |
| 27-43 | req_size | i128 | Requested size (+buy/-sell) |
| 43-67 | reserved | [u8;24] | Must be zero |

#### Response (64 bytes at offset 0 in context account)

| Offset | Field | Type | Description |
|--------|-------|------|-------------|
| 0-4 | abi_version | u32 | Always 3 |
| 4-8 | flags | u32 | VALID=1, PARTIAL_OK=2, REJECTED=4 |
| 8-16 | exec_price_e6 | u64 | Execution price |
| 16-32 | exec_size | i128 | Executed size |
| 32-40 | req_id | u64 | Echo of req_id |
| 40-48 | lp_account_id | u64 | Echo of lp_account_id |
| 48-56 | oracle_price_e6 | u64 | Echo of oracle_price_e6 |
| 56-64 | asset_index | u64 | Echo of asset_index |

### Tag 3: Batched Matcher Call (atomic multi-leg, from Percolator CPI)

Fills `n` legs against this LP's inventory in a single CPI. The LP PDA signs once for the whole batch; each leg runs the same passive matching logic as Tag 0, with inventory carried across legs in request order. The `n` returns are emitted via `sol_set_return_data` (the context account's 64-byte return slot holds only one), so `n` ≤ 16 (16 × 64 = the 1024-byte return-data cap). ABI version is unchanged (3).

#### Accounts

| Index | Name | Type | Description |
|-------|------|------|-------------|
| 0 | lp_pda | Signer | LP PDA (must match stored PDA) |
| 1 | matcher_ctx | Writable | Context account owned by this program |

#### Instruction Data (18 + n×26 bytes)

| Offset | Field | Type | Description |
|--------|-------|------|-------------|
| 0 | tag | u8 | Always 3 |
| 1 | n | u8 | Leg count (1..=16) |
| 2-10 | req_id | u64 | Batch request ID (echoed on every leg) |
| 10-18 | lp_account_id | u64 | LP account ID (echoed on every leg) |
| 18… | legs[n] | — | `n` legs, 26 bytes each (below) |

Each leg (26 bytes):

| Offset | Field | Type | Description |
|--------|-------|------|-------------|
| 0-2 | asset_index | u16 | Market asset index |
| 2-10 | oracle_price_e6 | u64 | Oracle price (1e6 scaled) |
| 10-26 | req_size | i128 | Requested size (+buy/-sell) |

#### Response (n × 64 bytes via return data)

`set_return_data` carries `n` back-to-back 64-byte `MatcherReturn` records — same layout as the Tag 0 response — one per leg in request order. The caller reads them with `get_return_data` (not from the context account).

### Tag 2: Initialize

Stores the LP PDA and parameters in the context account. The context account must sign
(it is a fresh keypair created in the same transaction), so a third party cannot bind
someone else's context. The LP PDA does not sign: it is the wrapper's matcher delegate and
can only sign through the wrapper's `invoke_signed`. Init only succeeds on a context region
that was never written; a context with any existing header, including the pre-`44d4cfa`
legacy magic, is refused.

#### Accounts

| Index | Name | Type | Description |
|-------|------|------|-------------|
| 0 | lp_pda | - | LP PDA to store (no signature required) |
| 1 | matcher_ctx | Signer, Writable | Context account owned by this program |

#### Instruction Data (66 bytes)

| Offset | Field | Type | Description |
|--------|-------|------|-------------|
| 0 | tag | u8 | Always 2 |
| 1 | kind | u8 | 0=Passive, 1=vAMM |
| 2-6 | trading_fee_bps | u32 | Trading fee in basis points |
| 6-10 | base_spread_bps | u32 | Base spread in basis points |
| 10-14 | max_total_bps | u32 | Maximum total spread/fee/impact |
| 14-18 | impact_k_bps | u32 | vAMM impact multiplier, 0 for passive |
| 18-34 | liquidity_notional_e6 | u128 | vAMM depth (≤ u64::MAX), 0 for passive |
| 34-50 | max_fill_abs | u128 | Maximum absolute fill per call |
| 50-66 | max_inventory_abs | u128 | Maximum absolute inventory per asset (≤ i128::MAX), 0 for no limit |

## Security

- **LP PDA binding**: The matcher verifies that the LP PDA signer matches the PDA stored during initialization
- **Authorized init**: The context account must sign tag 2
- **One-time init**: Context can only be initialized once, and never over existing bytes (prevents rebinding)
- **Upgrade migration**: Version-3 contexts are read as version 4 with their single inventory assigned to asset 0
- **Program ownership**: Context account must be owned by this program

## License

Apache 2.0

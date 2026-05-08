---
title: "WASM Smart Contract Security: CosmWasm and NEAR"
description: "WASM smart contracts in CosmWasm and NEAR inherit WASM sandboxing but introduce blockchain-specific risks: integer overflow in token math, reentrancy via cross-contract calls, and unsafe upgrade patterns. This guide covers audit methodology, secure coding patterns, and testing for Rust-based WASM contracts."
slug: wasm-smart-contract-security
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - smart-contracts
  - cosmwasm
  - near-protocol
  - blockchain
  - wasm
personas:
  - security-engineer
  - platform-engineer
article_number: 571
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/wasm-smart-contract-security/
---

# WASM Smart Contract Security: CosmWasm and NEAR

## Problem

WebAssembly's deterministic execution model and sandbox isolation make it a natural fit for blockchain smart contracts. Unlike the Ethereum Virtual Machine, which uses a purpose-built bytecode format tied to a single language ecosystem, WASM accepts compiled output from Rust, AssemblyScript, Go, and C — and executes identically on every validator node in the network. This portability and formal semantics are why CosmWasm (the Cosmos ecosystem) and NEAR Protocol both chose WASM as their contract execution layer.

The security properties WASM provides do not eliminate smart contract vulnerabilities — they shift them. WASM's sandbox prevents a malicious contract from escaping the host environment, but it does not prevent:

- **Integer overflow in token arithmetic.** Rust's arithmetic operators wrap on overflow in debug builds and can be configured to panic in release builds, but developers using raw `u128` or mixing numeric types in intermediate calculations risk producing incorrect fee values, zero-fee transfers, or negative balances that the type system does not catch.
- **Reentrancy via cross-contract calls.** Both CosmWasm and NEAR support calling other contracts from within a contract. If state is not committed before the outbound call, a malicious callee can call back into the original contract while its state is inconsistent — the same class as the Ethereum DAO vulnerability, reproduced in WASM.
- **Message ordering and reply handler attacks.** CosmWasm processes cross-contract calls via a message queue and reply handlers. An attacker who controls the called contract can return a crafted success reply with a manipulated payload, causing the reply handler to perform incorrect state transitions.
- **Admin key exposure and privilege escalation.** Contracts frequently have an owner or admin address with elevated permissions — migration, configuration, fund withdrawal. If the admin key is a plain keypair rather than a multisig, compromise of a single private key grants full control of the contract's funds and state.
- **Gas-based denial of service.** Loops over unbounded collections consume gas proportional to collection size. An attacker who can cause a contract to iterate over user-supplied data of arbitrary length can exhaust the gas limit, permanently blocking legitimate transactions.
- **Storage staking attacks (NEAR-specific).** NEAR Protocol requires contracts to stake NEAR tokens proportional to the on-chain storage they consume. A contract that allows callers to write unbounded data to per-caller storage slots can be forced to stake its entire balance, rendering it non-functional.

**Target systems:** CosmWasm 1.x and 2.x on Cosmos Hub, Osmosis, Neutron, Terra, Archway, and Juno; NEAR Protocol contracts compiled from Rust (`near-sdk-rs`) or AssemblyScript (`near-sdk-as`).

## Threat Model

- **Adversary 1 — Integer overflow for token theft:** A CosmWasm CW20 token contract calculates a fee as `amount * fee_bps / 10000` using a raw `u128` intermediate multiply. The attacker submits an amount large enough to overflow the intermediate, yielding a computed fee of zero and transferring a large balance without paying any fee.
- **Adversary 2 — Cross-contract reentrancy drain:** A CosmWasm vault contract sends funds to a user via `BankMsg::Send` and then updates the user's balance in storage. A malicious callee sends a callback before the balance update executes. The vault sends funds twice for a single withdrawal.
- **Adversary 3 — Reply handler manipulation:** A CosmWasm contract dispatches a cross-contract call with a `ReplyOn::Success` handler. The called contract is attacker-controlled and returns a crafted payload. The reply handler parses the payload and authorises an action that should not have been authorised.
- **Adversary 4 — Admin key compromise:** A NEAR contract stores `owner_id: AccountId` backed by a plain keypair. The private key is leaked. The attacker calls `transfer_ownership` then `withdraw_all`, draining the contract.
- **Adversary 5 — Gas exhaustion via large collection:** A NEAR contract stores registrations in a `Vector`. A privileged function iterates the entire vector. An attacker registers 100,000 accounts (paying the NEAR storage stake for each). The admin function now exceeds the gas limit and cannot execute.
- **Adversary 6 — Storage staking drain:** A NEAR contract allows any caller to write data to a per-caller storage slot without charging the caller for storage. An attacker writes large payloads under many accounts, forcing the contract to stake NEAR for all of it until the contract balance is consumed.
- **Access level:** Adversaries 1, 2, 3, 5, and 6 require only the ability to submit transactions — which any account with a small balance can do. Adversary 4 requires possession of the admin private key.
- **Blast radius:** Smart contracts are immutable by default, and on-chain fund transfers are irreversible. A contract that is exploited before the team can respond can be fully drained with no recovery path.

## Configuration

### Step 1: Checked Arithmetic in Token Math

All arithmetic on token amounts, balances, fees, and shares must use overflow-safe operations. In Rust — the dominant language for both CosmWasm and NEAR contracts — this means using `checked_*` methods and returning an error on overflow, or enabling `overflow-checks = true` in the release profile so that arithmetic operators panic rather than wrap.

```rust
// cosmwasm: token fee calculation with overflow protection.
use cosmwasm_std::{Uint128, StdResult, StdError};

pub fn calculate_fee(amount: Uint128, fee_bps: u64) -> StdResult<Uint128> {
    // BAD: amount.u128() * fee_bps as u128 / 10000
    //      The intermediate multiply can overflow u128 for very large amounts.

    // GOOD: cosmwasm_std::Uint128 uses checked arithmetic internally.
    let fee_bps_uint = Uint128::from(fee_bps);
    let numerator = amount
        .checked_mul(fee_bps_uint)
        .map_err(|_| StdError::generic_err("fee calculation overflow"))?;

    let fee = numerator
        .checked_div(Uint128::new(10_000))
        .map_err(|_| StdError::generic_err("fee divisor is zero"))?;

    Ok(fee)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_overflows_at_max_uint128() {
        // Must return an error, not silently produce a wrong value.
        let result = calculate_fee(Uint128::MAX, 9999);
        assert!(result.is_err());
    }

    #[test]
    fn fee_is_correct_for_normal_amounts() {
        let amount = Uint128::new(1_000_000); // 1 USDC (6 decimals).
        let fee = calculate_fee(amount, 30).unwrap(); // 0.3%.
        assert_eq!(fee, Uint128::new(3_000));
    }
}
```

Enable compiler-level overflow checks for both CosmWasm and NEAR contracts in `Cargo.toml`:

```toml
[profile.release]
overflow-checks = true   # Panic (abort tx) on integer overflow in release builds.
opt-level = "s"          # Optimise for binary size — reduces on-chain storage cost.
lto = true               # Link-time optimisation for smaller WASM output.
codegen-units = 1        # Single codegen unit for consistent determinism.
panic = "abort"          # Abort on panic — WASM does not support unwinding.
```

For NEAR contracts using `near-sdk-rs`, the same `Cargo.toml` settings apply. Use `Balance::checked_sub` instead of subtraction operators:

```rust
// near: safe balance subtraction.
use near_sdk::Balance; // type alias for u128.

pub fn safe_subtract(balance: Balance, amount: Balance) -> Result<Balance, String> {
    balance.checked_sub(amount).ok_or_else(|| {
        format!("Insufficient balance: have {}, need {}", balance, amount)
    })
}
```

### Step 2: Reentrancy Prevention in CosmWasm

CosmWasm's execution model is re-entrant by design: a contract calls another contract via a `CosmosMsg`, and the callee can call back into the original contract before the outer transaction completes. The canonical defence is the checks-effects-interactions pattern: commit all state changes before dispatching any external messages.

```rust
// cosmwasm: vault withdrawal using checks-effects-interactions.
use cosmwasm_std::{
    DepsMut, Env, MessageInfo, Response, BankMsg, Coin, StdResult, StdError,
};
use cw_storage_plus::Map;

const BALANCES: Map<&str, u128> = Map::new("balances");

pub fn execute_withdraw(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    amount: u128,
) -> StdResult<Response> {
    let sender = info.sender.as_str();

    // 1. CHECK: verify the caller has sufficient balance.
    let current = BALANCES.load(deps.storage, sender).unwrap_or(0);
    if current < amount {
        return Err(StdError::generic_err(format!(
            "Insufficient balance: have {}, requested {}",
            current, amount
        )));
    }

    // 2. EFFECT: update state BEFORE sending funds.
    //    If any downstream callback calls back into this contract,
    //    it will see the already-decremented balance.
    let new_balance = current
        .checked_sub(amount)
        .ok_or_else(|| StdError::generic_err("Balance underflow"))?;
    BALANCES.save(deps.storage, sender, &new_balance)?;

    // 3. INTERACTION: emit the bank message after state is committed.
    let send_msg = BankMsg::Send {
        to_address: info.sender.to_string(),
        amount: vec![Coin {
            denom: "uatom".to_string(),
            amount: amount.into(),
        }],
    };

    Ok(Response::new()
        .add_message(send_msg)
        .add_attribute("action", "withdraw")
        .add_attribute("amount", amount.to_string()))
}
```

For contracts that use sub-messages and reply handlers, never trust data from the reply payload for security decisions. Read your own pre-committed state instead:

```rust
// cosmwasm: safe reply handler — load state, do not trust reply payload.
use cosmwasm_std::{Reply, StdResult, Response, SubMsgResult, DepsMut, Env};
use crate::state::PENDING_OPERATION;

pub fn reply(deps: DepsMut, _env: Env, msg: Reply) -> StdResult<Response> {
    match msg.id {
        EXECUTE_SWAP_REPLY_ID => handle_swap_reply(deps, msg.result),
        id => Err(cosmwasm_std::StdError::generic_err(
            format!("Unknown reply id: {}", id),
        )),
    }
}

fn handle_swap_reply(deps: DepsMut, result: SubMsgResult) -> StdResult<Response> {
    match result {
        SubMsgResult::Ok(response) => {
            // Load the pending operation that was stored BEFORE the sub-message.
            let pending = PENDING_OPERATION.load(deps.storage)?;

            // Parse output from the reply only for informational purposes.
            let output_amount = parse_swap_output(&response.data)?;

            // Security decision based on pre-committed state, not attacker payload.
            if output_amount < pending.min_output {
                PENDING_OPERATION.remove(deps.storage);
                return Err(cosmwasm_std::StdError::generic_err(
                    "Swap output below minimum — slippage too high",
                ));
            }

            PENDING_OPERATION.remove(deps.storage);
            Ok(Response::new()
                .add_attribute("swap_output", output_amount.to_string()))
        }
        SubMsgResult::Err(err) => {
            PENDING_OPERATION.remove(deps.storage);
            Err(cosmwasm_std::StdError::generic_err(format!(
                "Sub-message failed: {}",
                err
            )))
        }
    }
}
```

### Step 3: Access Control — Admin and Owner Patterns

Both CosmWasm and NEAR contracts implement owner and admin roles. The access check must be the first operation in any privileged function, before any storage reads or writes that the caller should not influence.

For CosmWasm, use `cw-ownable` — a well-audited ownership primitive that enforces a two-step ownership transfer to prevent accidental transfer to a wrong or dead address:

```rust
// cosmwasm: ownership using cw-ownable.
use cw_ownable::{assert_owner, initialize_owner, Action};
use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, StdResult};

pub fn instantiate_with_owner(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    owner: Option<String>,
) -> StdResult<Response> {
    let owner_addr = owner.unwrap_or_else(|| info.sender.to_string());
    initialize_owner(deps.storage, deps.api, Some(&owner_addr))?;
    Ok(Response::new().add_attribute("owner", owner_addr))
}

pub fn execute_update_config(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    new_fee_bps: u64,
) -> StdResult<Response> {
    // assert_owner returns Err immediately if info.sender is not the stored owner.
    assert_owner(deps.storage, &info.sender)?;

    if new_fee_bps > 1000 {
        return Err(cosmwasm_std::StdError::generic_err(
            "Fee cannot exceed 10% (1000 bps)",
        ));
    }

    CONFIG.save(deps.storage, &Config { fee_bps: new_fee_bps })?;

    Ok(Response::new()
        .add_attribute("action", "update_config")
        .add_attribute("fee_bps", new_fee_bps.to_string()))
}

// Two-step ownership transfer: new owner must explicitly accept.
pub fn execute_transfer_ownership(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    new_owner: String,
    expiry: Option<cw_ownable::Expiration>,
) -> StdResult<Response> {
    cw_ownable::update_ownership(
        deps,
        &env.block,
        &info.sender,
        Action::TransferOwnership { new_owner, expiry },
    )?;
    Ok(Response::default())
}
```

For NEAR Protocol, implement role-based access control with explicit account validation. Use multisig accounts for the `owner_id` in production — plain keypair accounts are a single point of failure:

```rust
// near: role-based access control with owner and admin roles.
use near_sdk::{near_bindgen, AccountId, env, Promise};
use near_sdk::collections::UnorderedSet;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct Contract {
    owner_id: AccountId,
    admins: UnorderedSet<AccountId>,
}

#[near_bindgen]
impl Contract {
    fn assert_owner(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only the owner can call this function"
        );
    }

    fn assert_admin(&self) {
        let caller = env::predecessor_account_id();
        assert!(
            caller == self.owner_id || self.admins.contains(&caller),
            "Caller {} is not an admin",
            caller
        );
    }

    // Owner-only: add a new admin.
    pub fn add_admin(&mut self, account_id: AccountId) {
        self.assert_owner();
        self.admins.insert(&account_id);
    }

    // Owner-only: withdraw funds from the contract.
    pub fn withdraw(&mut self, amount: near_sdk::Balance) -> Promise {
        self.assert_owner();
        let balance = env::account_balance();
        assert!(
            amount <= balance,
            "Cannot withdraw {} — contract balance is {}",
            amount,
            balance
        );
        Promise::new(self.owner_id.clone()).transfer(amount)
    }
}
```

### Step 4: Gas Estimation and DoS Prevention

Any loop whose iteration count grows with user-supplied data is a gas DoS vector. Use bounded iteration — cap the number of elements processed per transaction — and require callers to paginate through large collections.

For NEAR contracts, apply a hard per-call limit:

```rust
// near: paginated iteration to avoid gas exhaustion.
use near_sdk::near_bindgen;
use near_sdk::collections::Vector;

const MAX_ITEMS_PER_CALL: u64 = 100;

#[near_bindgen]
impl Contract {
    // UNSAFE — iterates all registrations; DoS if count is large:
    // pub fn count_active(&self) -> u64 {
    //     self.registrations.iter().filter(|r| r.active).count() as u64
    // }

    // SAFE: paginated with a hard bound.
    pub fn count_active_paginated(
        &self,
        from_index: u64,
        limit: Option<u64>,
    ) -> (u64, bool) {
        let limit = limit
            .unwrap_or(MAX_ITEMS_PER_CALL)
            .min(MAX_ITEMS_PER_CALL);
        let len = self.registrations.len();

        if from_index >= len {
            return (0, false);
        }

        let end = (from_index + limit).min(len);
        let mut count = 0u64;
        for i in from_index..end {
            if let Some(reg) = self.registrations.get(i) {
                if reg.active {
                    count += 1;
                }
            }
        }

        (count, end < len) // has_more flag drives client pagination.
    }
}
```

For CosmWasm storage queries, use `.take()` to enforce a hard page size regardless of what the caller requests:

```rust
// cosmwasm: bounded storage iteration.
use cosmwasm_std::{Deps, Order, StdResult};
use cw_storage_plus::{Map, Bound};

const REGISTRATIONS: Map<&str, Registration> = Map::new("registrations");
const PAGE_SIZE: usize = 50;

pub fn query_registrations(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<Vec<Registration>> {
    // Enforce a maximum page size regardless of caller input.
    let limit = limit
        .unwrap_or(PAGE_SIZE as u32)
        .min(PAGE_SIZE as u32) as usize;

    let start = start_after.as_deref().map(Bound::exclusive);

    REGISTRATIONS
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit) // Hard bound: never more than PAGE_SIZE iterations.
        .map(|item| item.map(|(_, v)| v))
        .collect()
}
```

### Step 5: NEAR Protocol Storage Staking and Deposit Guards

NEAR requires contracts to stake tokens proportional to on-chain storage. Guard every write path with storage-cost accounting: measure storage delta, charge the caller for it, and refund the deposit when data is deleted.

```rust
// near: storage staking guard following NEP-145 conventions.
use near_sdk::{near_bindgen, env, Promise, Balance};

const STORAGE_COST_PER_BYTE: Balance = 10_000_000_000_000_000_000; // 10^19 yoctoNEAR.
const MAX_DATA_SIZE: usize = 4096; // Hard cap: 4 KiB per registration.

#[near_bindgen]
impl Contract {
    #[payable]
    pub fn register(&mut self, data: String) {
        // 1. Validate input size to bound storage consumption.
        assert!(
            data.len() <= MAX_DATA_SIZE,
            "Data too large: {} bytes, max is {}",
            data.len(),
            MAX_DATA_SIZE
        );

        let account_id = env::predecessor_account_id();
        let storage_before = env::storage_usage();

        self.registrations.insert(&account_id, &data);

        // 2. Measure exact storage delta and charge caller accordingly.
        let storage_used = (env::storage_usage() - storage_before) as u128;
        let required_deposit = storage_used * STORAGE_COST_PER_BYTE;

        let attached = env::attached_deposit();
        assert!(
            attached >= required_deposit,
            "Attached {} yoctoNEAR but need {} for {} bytes of storage",
            attached,
            required_deposit,
            storage_used
        );

        // 3. Refund excess deposit to the caller.
        let refund = attached - required_deposit;
        if refund > 1 {
            Promise::new(account_id).transfer(refund);
        }
    }

    // Deregister: free storage and refund the proportional NEAR deposit.
    pub fn deregister(&mut self) -> Promise {
        let account_id = env::predecessor_account_id();
        let storage_before = env::storage_usage();
        self.registrations.remove(&account_id);
        let storage_freed = (storage_before - env::storage_usage()) as u128;
        let refund = storage_freed * STORAGE_COST_PER_BYTE;
        Promise::new(account_id).transfer(refund)
    }
}
```

### Step 6: Secure Upgrade Patterns and Migration Functions

CosmWasm contracts are upgradeable if the instantiator grants the `admin` role to an address. Without a timelock, a compromised admin key can deploy a malicious replacement instantly — before the team can detect or respond. Implement a two-step migration with a 48-hour delay:

```rust
// cosmwasm: migration timelock.
use cosmwasm_std::{DepsMut, Env, MessageInfo, Response, StdResult, Timestamp};
use cw_storage_plus::Item;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PendingMigration {
    pub new_code_id: u64,
    pub proposed_at: Timestamp,
    pub proposer: String,
}

const PENDING_MIGRATION: Item<PendingMigration> = Item::new("pending_migration");
const MIGRATION_TIMELOCK_SECONDS: u64 = 48 * 60 * 60; // 48-hour delay.

// Step 1: propose migration; starts the timelock clock.
pub fn execute_propose_migration(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    new_code_id: u64,
) -> StdResult<Response> {
    assert_owner(deps.storage, &info.sender)?;

    if PENDING_MIGRATION.may_load(deps.storage)?.is_some() {
        return Err(cosmwasm_std::StdError::generic_err(
            "A migration is already pending; cancel it first",
        ));
    }

    PENDING_MIGRATION.save(deps.storage, &PendingMigration {
        new_code_id,
        proposed_at: env.block.time,
        proposer: info.sender.to_string(),
    })?;

    Ok(Response::new()
        .add_attribute("action", "propose_migration")
        .add_attribute("new_code_id", new_code_id.to_string())
        .add_attribute(
            "executable_after",
            (env.block.time.seconds() + MIGRATION_TIMELOCK_SECONDS).to_string(),
        ))
}

// Step 2: confirm migration only after the timelock has elapsed.
pub fn execute_confirm_migration(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> StdResult<Response> {
    assert_owner(deps.storage, &info.sender)?;

    let pending = PENDING_MIGRATION
        .load(deps.storage)
        .map_err(|_| cosmwasm_std::StdError::generic_err("No pending migration"))?;

    let elapsed = env.block.time.seconds() - pending.proposed_at.seconds();
    if elapsed < MIGRATION_TIMELOCK_SECONDS {
        return Err(cosmwasm_std::StdError::generic_err(format!(
            "Timelock not elapsed: {} seconds remaining",
            MIGRATION_TIMELOCK_SECONDS - elapsed
        )));
    }

    PENDING_MIGRATION.remove(deps.storage);

    Ok(Response::new()
        .add_attribute("action", "migration_confirmed")
        .add_attribute("new_code_id", pending.new_code_id.to_string()))
}
```

The `migrate()` entrypoint itself must validate that it is being called from a known prior version and reject unknown versions explicitly:

```rust
// cosmwasm: safe migrate() entrypoint.
use cosmwasm_std::{DepsMut, Env, Response, StdResult};
use cw2::{get_contract_version, set_contract_version};

const CONTRACT_NAME: &str = "crates.io:my-vault";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    let version = get_contract_version(deps.storage)?;

    // Reject migration from unknown versions to prevent accidental downgrades
    // or upgrades from a state shape this migration does not know how to handle.
    match version.version.as_str() {
        "1.0.0" => migrate_from_v1(deps.storage)?,
        "1.1.0" => migrate_from_v1_1(deps.storage)?,
        v => {
            return Err(cosmwasm_std::StdError::generic_err(format!(
                "Cannot migrate from unknown version: {}",
                v
            )));
        }
    }

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new()
        .add_attribute("action", "migrate")
        .add_attribute("from_version", version.version)
        .add_attribute("to_version", CONTRACT_VERSION))
}
```

### Step 7: Audit Methodology — cargo-audit, cargo-fuzz, and Formal Approaches

Smart contract audits combine automated dependency scanning, fuzz testing on entry points, and manual review of business logic.

**Static analysis and dependency scanning:**

```bash
# Check all dependencies for known CVEs.
cargo audit

# Enforce dependency policy: licences, banned crates, duplicate versions.
cargo deny check

# Clippy with security-relevant lints.
cargo clippy -- \
  -D warnings \
  -W clippy::integer_arithmetic \
  -W clippy::arithmetic_side_effects \
  -W clippy::unwrap_used \
  -W clippy::expect_used
```

**Integration testing with cw-multi-test:**

```rust
// cosmwasm: integration test for reentrancy scenario.
#[cfg(test)]
mod integration_tests {
    use cosmwasm_std::{Addr, Coin};
    use cw_multi_test::{App, ContractWrapper, Executor};

    #[test]
    fn double_withdrawal_is_rejected() {
        let mut app = App::default();

        let vault_code = app.store_code(Box::new(ContractWrapper::new(
            crate::execute,
            crate::instantiate,
            crate::query,
        )));

        let vault_addr = app
            .instantiate_contract(
                vault_code,
                Addr::unchecked("owner"),
                &InstantiateMsg {},
                &[Coin::new(10_000_000, "uatom")],
                "vault",
                None,
            )
            .unwrap();

        // Deposit 1,000,000 uatom.
        app.execute_contract(
            Addr::unchecked("attacker"),
            vault_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[Coin::new(1_000_000, "uatom")],
        )
        .unwrap();

        // First withdrawal must succeed.
        app.execute_contract(
            Addr::unchecked("attacker"),
            vault_addr.clone(),
            &ExecuteMsg::Withdraw { amount: 1_000_000u128.into() },
            &[],
        )
        .unwrap();

        // Second withdrawal of the same amount must fail — balance is zero.
        let result = app.execute_contract(
            Addr::unchecked("attacker"),
            vault_addr.clone(),
            &ExecuteMsg::Withdraw { amount: 1_000_000u128.into() },
            &[],
        );
        assert!(result.is_err(), "Double withdrawal must be rejected");
    }
}
```

**Fuzz testing contract entry points with `cargo-fuzz`:**

```rust
// fuzz/fuzz_targets/execute.rs — fuzz the contract's execute handler.
#![no_main]
use libfuzzer_sys::fuzz_target;
use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = serde_json::from_slice::<ExecuteMsg>(data) {
        let mut deps = mock_dependencies();
        let _ = instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("creator", &[]),
            InstantiateMsg::default(),
        );
        // Must never panic; must return Ok or Err.
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("attacker", &[]),
            msg,
        );
    }
});
```

```bash
# Run the fuzzer with a bounded corpus to catch panics and state corruption.
cargo +nightly fuzz run execute -- \
  -max_len=4096 \
  -timeout=10 \
  -runs=500000
```

**Formal verification approaches** for CosmWasm and NEAR contracts are an active area. Tools like `kani` (Rust model checker) can verify bounded properties — such as the absence of integer overflow on specific code paths — without requiring exhaustive fuzzing. For critical financial contracts, theorem-proving frameworks like `Coq` or `Lean` have been applied to verify invariants about token supply conservation and access control correctness, though these require significant expertise. For most production contracts, the practical baseline is: `cargo-audit` in CI, `cargo-fuzz` corpus for entry points, and `cw-multi-test` integration tests covering adversarial cross-contract scenarios.

### Step 8: On-Chain Monitoring and Alerting

Smart contracts are immutable at the code level but their state is observable. Off-chain monitoring of state changes, large transfers, and privileged operations provides an early-warning system.

```
cosmwasm_contract_balance_change{contract, denom}     gauge      # Watch for unexpected fund drain.
cosmwasm_admin_action_total{contract, action}         counter    # Count privileged operations.
cosmwasm_migrate_proposed{contract, new_code_id}      event      # Alert on migration proposals.
near_contract_storage_bytes{contract}                 gauge      # Watch for storage growth attacks.
near_access_key_added{contract, account}              event      # Alert on key additions to accounts.
near_withdrawal_amount{contract, recipient}           histogram  # Flag large withdrawals.
contract_cross_call_depth{contract}                   gauge      # Deep call stacks may indicate reentrancy.
```

Alert thresholds:

- `cosmwasm_contract_balance_change` dropping more than 20% in a single block — notify security team immediately for possible fund drain.
- `cosmwasm_migrate_proposed` — a migration proposal has been submitted; team must review the new code ID before the 48-hour timelock elapses.
- `near_contract_storage_bytes` growing faster than expected registration rate — possible storage staking attack in progress.
- `cosmwasm_admin_action_total{action="transfer_ownership"}` — verify through an out-of-band channel that the ownership transfer was intentional before it is accepted.
- `contract_cross_call_depth` exceeding 3 — investigate for unexpected reentrancy or call stack manipulation.

## Expected Behaviour

| Signal | Unprotected contract | Hardened contract |
|---|---|---|
| Integer overflow in token math | Wraps to zero; incorrect fee charged | `overflow-checks = true` aborts transaction; no state change |
| Reentrancy withdrawal attempt | Funds sent twice; balance goes negative | Balance committed before send; second withdrawal rejected with error |
| Unbounded loop over user-supplied data | Gas limit exceeded; function permanently unusable | `.take(PAGE_SIZE)` bounds iteration; function always completes |
| Admin key compromise | Attacker upgrades or drains contract instantly | 48-hour timelock gives team a response window |
| NEAR storage staking drain | Contract stakes unlimited NEAR for attacker data | Caller pays exact storage deposit; max data size enforced |
| Reply handler manipulation | Attacker payload authorises unintended action | Security decision based on pre-committed state, not reply payload |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| `overflow-checks = true` | Eliminates integer overflow class | Small gas increase (~2–5%) | Acceptable for correctness; benchmark critical paths |
| Checks-effects-interactions | Eliminates reentrancy class | Requires discipline in every stateful function | Code review checklist; automated lint |
| Migration timelock (48 h) | Response window for compromised admin key | Emergency patches cannot apply instantly | Maintain a guardian multisig that can cancel pending migrations |
| Paginated iteration | Bounded gas; function always executable | Clients must implement pagination | Provide view functions for counts and pagination helpers |
| Storage deposit charge (NEAR) | Prevents storage staking drain | Friction for legitimate callers | Provide `storage_deposit` entry point per NEP-145 |
| cw-multi-test integration tests | Catches cross-contract bugs before deployment | Slower CI | Run unit tests for pure logic; integration tests for message flows |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Overflow check aborts legitimate transaction | Valid large token transfer reverts on mainnet | Transaction failure in testnet with max amounts | Use `saturating_*` where truncation is acceptable; `checked_*` where it is not |
| Migration timelock blocks emergency fix | Critical bug cannot be patched for 48 hours | Known bug with active exploitation | Guardian multisig with timelock-cancel capability; documented incident runbook |
| Paginated query misses items | Clients see partial data | Query returns `has_more: true`; client ignores it | Document pagination contract; SDK helpers that auto-paginate |
| NEAR storage refund underflow | `deregister` panics on inaccurate delta | Panic in testnet deregister call | Measure storage delta at save/remove time; invariant tests |
| Reply ID collision | Wrong handler processes reply; state corrupted | Test with multiple concurrent sub-messages | Use distinct enum-backed constants for all reply IDs; reject unknown IDs |

## Related Articles

- [WASM Linear Memory Safety](/articles/wasm/wasm-linear-memory-safety/)
- [WASM Static Analysis](/articles/wasm/wasm-static-analysis/)
- [OPA WASM Policy Compilation](/articles/wasm/opa-wasm-policy/)
- [WASM Supply Chain Scanning Tools](/articles/wasm/wasm-supply-chain-scanning-tools/)
- [WASM Component Model Security](/articles/wasm/wasm-component-model-security/)

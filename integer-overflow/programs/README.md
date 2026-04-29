# Programs Directory

This directory contains two Anchor programs demonstrating **Integer Overflow/Underflow** vulnerabilities and their fix.

---

## The Attack in Detail

VaultProtocol's `withdraw()` subtracts the withdrawal amount from the user's balance without checking if they have enough funds:

1. User deposits 100 lamports → `balance = 100`
2. User withdraws 200 lamports → `balance = 100 - 200`
3. Underflow wraps: `balance = 18,446,744,073,709,551,515`
4. User drains the entire vault with their "astronomical" balance

---

## Why This Happens

In Rust **release builds** (how Solana programs compile), arithmetic operations **wrap silently**:

| Operation | Result |
|-----------|--------|
| `0u64 - 1` | `18,446,744,073,709,551,615` (u64::MAX) |
| `u64::MAX + 1` | `0` |

Debug builds would panic, but production doesn't — the bug only manifests live.

---

## Program Overview

### 📁 `vulnerable/`

Uses unchecked arithmetic — wraps silently on underflow.

```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let user = &mut ctx.accounts.user_account;
    
    // VULNERABLE: No bounds check!
    // 100 - 200 = u64::MAX - 99
    user.balance = user.balance.wrapping_sub(amount);
    
    // Transfer funds...
    Ok(())
}
```

---

### 📁 `secure/`

Uses checked arithmetic — returns error on underflow.

```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let user = &mut ctx.accounts.user_account;
    
    // SECURE: checked_sub returns None if balance < amount
    user.balance = user.balance
        .checked_sub(amount)
        .ok_or(ErrorCode::InsufficientFunds)?;
    
    // Transfer funds...
    Ok(())
}
```

---

## Comparison

| Aspect | Vulnerable | Secure |
|--------|------------|--------|
| `100 - 200` | `u64::MAX - 99` | `Err(InsufficientFunds)` |
| Arithmetic | `wrapping_sub` / raw `-` | `checked_sub` |
| State Corruption | ✅ Possible | ❌ Prevented |

---

## Checked Arithmetic Methods

| Method | Behavior | Use Case |
|--------|----------|----------|
| `checked_add(n)` | Returns `None` on overflow | Deposits, totals |
| `checked_sub(n)` | Returns `None` on underflow | Withdrawals, balances |
| `checked_mul(n)` | Returns `None` on overflow | Fee calculations |
| `saturating_sub(n)` | Clamps to 0 | Counters that shouldn't go negative |

---

## State

```rust
#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub total_deposits: u64,
}

#[account]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
}
```

---

## Instructions

| Instruction | Description |
|-------------|-------------|
| `initialize_vault` | Create vault with initial protocol funds |
| `create_user_account` | Create PDA account for user |
| `deposit` | User deposits SOL into their account |
| `withdraw` | User withdraws SOL from their account |

---

## Building

```bash
anchor build -p vulnerable
anchor build -p secure
```

---

## Key Takeaway

**Solana programs run in release mode — arithmetic wraps silently.**

Always use `checked_*` methods for any arithmetic involving user funds:

```rust
balance.checked_sub(amount).ok_or(Error::InsufficientFunds)?
```

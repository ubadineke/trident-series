use anchor_lang::prelude::*;

declare_id!("AFPFRXtPsmj21pQNQQQmsFBYjXbxAhyPDLby3DmU73X6");

/// ============================================================================
/// SECURE PROGRAM: Integer Overflow/Underflow Prevention
/// ============================================================================
/// This program demonstrates the SECURE way to handle arithmetic operations
/// using Rust's checked arithmetic methods:
///
/// - checked_add()  → Returns None on overflow
/// - checked_sub()  → Returns None on underflow
/// - checked_mul()  → Returns None on overflow
/// - saturating_*() → Clamps to min/max instead of wrapping
///
/// These methods prevent silent wrapping and allow proper error handling.
/// ============================================================================

#[program]
pub mod secure {
    use super::*;

    /// Initialize the vault with funds (admin deposits protocol funds)
    pub fn initialize_vault(ctx: Context<InitializeVault>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.total_deposits = amount;

        // Transfer SOL from authority to vault
        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.authority.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;

        msg!("Vault initialized with {} lamports", amount);
        Ok(())
    }

    /// User creates their account
    pub fn create_user_account(ctx: Context<CreateUserAccount>) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;
        user_account.owner = ctx.accounts.user.key();
        user_account.balance = 0;

        msg!("User account created for {}", ctx.accounts.user.key());
        Ok(())
    }

    /// User deposits funds
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;

        // =====================================================================
        // SECURE: Using checked_add() to prevent overflow
        // =====================================================================
        // checked_add() returns Option<u64>:
        // - Some(result) if addition is safe
        // - None if overflow would occur
        //
        // We convert None to an error using ok_or()
        // =====================================================================
        user_account.balance = user_account
            .balance
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;

        // Update vault total with overflow protection
        let vault = &mut ctx.accounts.vault;
        vault.total_deposits = vault
            .total_deposits
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;

        // Transfer SOL from user to vault
        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.user.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;

        msg!(
            "User deposited {} lamports, new balance: {}",
            amount,
            user_account.balance
        );
        Ok(())
    }

    /// User withdraws funds from their account
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let user_account = &mut ctx.accounts.user_account;

        // =====================================================================
        // SECURE: Using checked_sub() to prevent underflow
        // =====================================================================
        // checked_sub() returns Option<u64>:
        // - Some(result) if subtraction is safe (balance >= amount)
        // - None if underflow would occur (balance < amount)
        //
        // This prevents the attack where:
        //   100 - 200 would underflow to u64::MAX - 99
        //
        // Instead, we get None and return InsufficientFunds error
        // =====================================================================
        user_account.balance = user_account
            .balance
            .checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;

        // Update vault total with underflow protection
        let vault = &mut ctx.accounts.vault;
        vault.total_deposits = vault
            .total_deposits
            .checked_sub(amount)
            .ok_or(ErrorCode::Underflow)?;

        // Transfer SOL from vault to user
        let vault_info = ctx.accounts.vault.to_account_info();
        let user_info = ctx.accounts.user.to_account_info();

        let new_vault_balance = vault_info
            .lamports()
            .checked_sub(amount)
            .ok_or(ErrorCode::Underflow)?;
        **vault_info.try_borrow_mut_lamports()? = new_vault_balance;

        let new_user_balance = user_info
            .lamports()
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        **user_info.try_borrow_mut_lamports()? = new_user_balance;

        msg!(
            "User withdrew {} lamports, new balance: {}",
            amount,
            user_account.balance
        );
        Ok(())
    }
}

// =============================================================================
// Account Structures
// =============================================================================

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = 8 + Vault::INIT_SPACE,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, Vault>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateUserAccount<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        init,
        payer = user,
        space = 8 + UserAccount::INIT_SPACE,
        seeds = [b"user", user.key().as_ref()],
        bump
    )]
    pub user_account: Account<'info, UserAccount>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"user", user.key().as_ref()],
        bump
    )]
    pub user_account: Account<'info, UserAccount>,

    #[account(
        mut,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, Vault>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"user", user.key().as_ref()],
        bump,
        has_one = owner @ ErrorCode::Unauthorized
    )]
    pub user_account: Account<'info, UserAccount>,

    /// CHECK: Verified via has_one
    #[account(constraint = user_account.owner == user.key())]
    pub owner: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, Vault>,
}

// =============================================================================
// State Accounts
// =============================================================================

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub total_deposits: u64,
}

#[account]
#[derive(InitSpace)]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
}

// =============================================================================
// Errors
// =============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Arithmetic underflow")]
    Underflow,
    #[msg("Insufficient funds for withdrawal")]
    InsufficientFunds,
}

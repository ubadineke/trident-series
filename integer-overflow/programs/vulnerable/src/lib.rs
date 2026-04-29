use anchor_lang::prelude::*;

declare_id!("Gb1FA4kQRi5Ci2kChRbg2f8pTaqcutyAbCDciQxFQUf2");

/// ============================================================================
/// VULNERABLE PROGRAM: Integer Overflow/Underflow Demonstration
/// ============================================================================
/// This program demonstrates integer overflow/underflow vulnerabilities where
/// arithmetic operations are performed without bounds checking.
///
/// In Rust release builds (how Solana programs compile), integer operations
/// wrap around silently instead of panicking:
/// - Underflow: 0u64 - 1 = u64::MAX (18,446,744,073,709,551,615)
/// - Overflow: u64::MAX + 1 = 0
/// ============================================================================

#[program]
pub mod vulnerable {
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
        // VULNERABILITY: Unchecked addition - potential overflow
        // =====================================================================
        // If user.balance is near u64::MAX, adding more could overflow to 0
        // Example: u64::MAX + 1 = 0
        // In practice, underflow in withdraw() is more exploitable
        //
        // NOTE: Using wrapping_add() to demonstrate overflow behavior in tests.
        // In production release builds, standard `+` wraps silently.
        // =====================================================================
        user_account.balance = user_account.balance.wrapping_add(amount);

        // Update vault total
        let vault = &mut ctx.accounts.vault;
        vault.total_deposits = vault.total_deposits.wrapping_add(amount);

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
        // VULNERABILITY: Unchecked subtraction - UNDERFLOW!
        // =====================================================================
        // This is the critical vulnerability. No check if balance >= amount.
        // If user.balance = 100 and amount = 200:
        //   100 - 200 = 18,446,744,073,709,551,515 (u64::MAX - 99)
        //
        // The user's balance UNDERFLOWS and becomes astronomically large!
        // They can then withdraw the entire vault.
        //
        // NOTE: In production (release builds), standard `-` would wrap silently.
        // We use wrapping_sub() here to demonstrate the vulnerability in tests,
        // since tests run in debug mode where `-` would panic.
        // =====================================================================
        // user_account.balance = user_account.balance.wrapping_sub(amount);
        user_account.balance = user_account.balance.wrapping_sub(amount);

        // Update vault total (this will also underflow if vault < amount)
        let vault = &mut ctx.accounts.vault;
        vault.total_deposits = vault.total_deposits.wrapping_sub(amount);

        // Transfer SOL from vault to user
        let vault_info = ctx.accounts.vault.to_account_info();
        let user_info = ctx.accounts.user.to_account_info();

        **vault_info.try_borrow_mut_lamports()? -= amount;
        **user_info.try_borrow_mut_lamports()? += amount;

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
}

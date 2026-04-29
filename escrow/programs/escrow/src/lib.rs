use anchor_lang::prelude::*;

declare_id!("escrWWM1M3eA87HpqPuy7g2jEqZudP413zUa1m4oA2w");

#[program]
pub mod escrow {
    use super::*;

    pub fn initialize_escrow(ctx: Context<InitializeEscrow>, amount: u64) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        escrow.depositor = ctx.accounts.depositor.key();
        escrow.counterparty = ctx.accounts.counterparty.key();
        escrow.amount = amount;
        escrow.status = EscrowStatus::Initialized as u8;
        escrow.bump = ctx.bumps.escrow;
        Ok(())
    }

    pub fn fund_escrow(ctx: Context<FundEscrow>, amount: u64) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        
        // BUG 1 (State Machine): No status check before funding
        // require!(escrow.status == EscrowStatus::Initialized as u8, EscrowError::InvalidStatus);

        // BUG 2 (Conservation): Amount overwrite instead of validation
        escrow.amount = amount;
        escrow.status = EscrowStatus::Funded as u8;

        let cur_lamports = ctx.accounts.depositor.lamports();
        if cur_lamports < amount {
            return err!(EscrowError::InsufficientFunds);
        }

        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.depositor.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;

        Ok(())
    }

    pub fn exchange(ctx: Context<Exchange>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;

        // BUG 3 (State Machine): No status check (can exchange unfunded escrow)
        // require!(escrow.status == EscrowStatus::Funded as u8, EscrowError::InvalidStatus);

        // BUG 4 (Authorization): No counterparty verification (anyone can claim)
        // require!(ctx.accounts.taker.key() == escrow.counterparty, EscrowError::Unauthorized);

        escrow.status = EscrowStatus::Exchanged as u8;

        let vault_lamports = ctx.accounts.vault.lamports();
        **ctx.accounts.vault.try_borrow_mut_lamports()? -= vault_lamports;
        **ctx.accounts.taker.try_borrow_mut_lamports()? += vault_lamports;

        Ok(())
    }

    pub fn cancel_escrow(ctx: Context<CancelEscrow>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;

        // Status check correctly exists since the bug spec only wants a bug on auth, not status here
        require!(
            escrow.status == EscrowStatus::Initialized as u8 || escrow.status == EscrowStatus::Funded as u8,
            EscrowError::InvalidStatus
        );

        // BUG 5 (Authorization): No auth check on canceller (anyone can cancel)
        // require!(ctx.accounts.canceller.key() == escrow.depositor, EscrowError::Unauthorized);

        escrow.status = EscrowStatus::Cancelled as u8;

        let vault_lamports = ctx.accounts.vault.lamports();
        **ctx.accounts.vault.try_borrow_mut_lamports()? -= vault_lamports;
        **ctx.accounts.depositor.try_borrow_mut_lamports()? += vault_lamports;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeEscrow<'info> {
    #[account(mut)]
    pub depositor: Signer<'info>,
    
    #[account(
        init,
        payer = depositor,
        space = 8 + EscrowState::INIT_SPACE,
        seeds = [b"escrow", depositor.key().as_ref()],
        bump
    )]
    pub escrow: Account<'info, EscrowState>,
    
    /// CHECK: Safe, just recording the pubkey
    pub counterparty: UncheckedAccount<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FundEscrow<'info> {
    #[account(mut)]
    pub depositor: Signer<'info>,
    
    #[account(mut)]
    pub escrow: Account<'info, EscrowState>,
    
    #[account(
        mut,
        seeds = [b"vault", escrow.key().as_ref()],
        bump
    )]
    /// CHECK: PDA handled carefully
    pub vault: SystemAccount<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Exchange<'info> {
    #[account(mut)]
    pub taker: Signer<'info>,
    
    #[account(mut)]
    pub escrow: Account<'info, EscrowState>,
    
    #[account(mut)]
    /// CHECK: PDA handled carefully
    pub vault: SystemAccount<'info>,
}

#[derive(Accounts)]
pub struct CancelEscrow<'info> {
    #[account(mut)]
    pub canceller: Signer<'info>,
    
    #[account(mut)]
    pub escrow: Account<'info, EscrowState>,
    
    #[account(mut)]
    /// CHECK: PDA handled carefully
    pub vault: SystemAccount<'info>,
    
    #[account(mut)]
    /// CHECK: Refund target
    pub depositor: SystemAccount<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct EscrowState {
    pub depositor: Pubkey,
    pub counterparty: Pubkey,
    pub amount: u64,
    pub status: u8,
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq)]
pub enum EscrowStatus {
    Initialized = 0,
    Funded = 1,
    Exchanged = 2,
    Cancelled = 3,
}

#[error_code]
pub enum EscrowError {
    #[msg("Invalid escrow status for this operation")]
    InvalidStatus,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Amount mismatch")]
    AmountMismatch,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Already funded")]
    AlreadyFunded,
}


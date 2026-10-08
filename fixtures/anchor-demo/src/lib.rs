//! Anchor test program for sbpf-inspect. Each item exercises one recovery case;
//! tests/fixtures.rs asserts what the engine must and must not find.
use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod inspect_fixture_anchor {
    use super::*;

    /// Plain single-word handler.
    pub fn initialize(ctx: Context<Initialize>, fee_bps: u16) -> Result<()> {
        let settings = &mut ctx.accounts.settings;
        settings.authority = ctx.accounts.authority.key();
        settings.fee_bps = fee_bps;
        emit!(SettingsChanged { fee_bps });
        Ok(())
    }

    /// Letter-digit word: logged `DepositV2`, hashed `deposit_v2`.
    pub fn deposit_v2(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.total = vault.total.checked_add(amount).ok_or(FixtureError::Overflow)?;
        // Puts the event name in the binary's strings, so the event path is exercised.
        msg!("emitting VaultDeposited");
        emit!(VaultDeposited { amount });
        Ok(())
    }

    /// Digit spelling heck does not produce: logged `Step2`, hashed `step_2`.
    pub fn step_2(_ctx: Context<Touch>) -> Result<()> {
        Ok(())
    }

    /// Multi-word handler with a `has_one` constraint.
    pub fn set_authority(ctx: Context<SetAuthority>, new_authority: Pubkey) -> Result<()> {
        ctx.accounts.settings.authority = new_authority;
        Ok(())
    }
}

#[account]
pub struct Settings {
    pub authority: Pubkey,
    pub fee_bps: u16,
}

#[account]
pub struct Vault {
    pub total: u64,
}

/// Name never appears in the binary's strings: must stay unrecovered.
#[event]
pub struct SettingsChanged {
    pub fee_bps: u16,
}

/// Name appears through the `msg!` above: must be recovered.
#[event]
pub struct VaultDeposited {
    pub amount: u64,
}

#[error_code]
pub enum FixtureError {
    #[msg("amount overflow")]
    Overflow,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32 + 2)]
    pub settings: Account<'info, Settings>,
    #[account(init, payer = authority, space = 8 + 8)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
pub struct Touch<'info> {
    pub settings: Account<'info, Settings>,
}

#[derive(Accounts)]
pub struct SetAuthority<'info> {
    #[account(mut, has_one = authority)]
    pub settings: Account<'info, Settings>,
    pub authority: Signer<'info>,
}

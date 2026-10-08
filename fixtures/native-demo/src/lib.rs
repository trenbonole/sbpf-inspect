//! Native (non-Anchor) test program for sbpf-inspect. It logs a string shaped
//! like an Anchor instruction log, with no discriminator behind it: the engine
//! must not report an instruction or call the program Anchor.
use solana_program::{account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg, pubkey::Pubkey};

entrypoint!(process_instruction);

pub fn process_instruction(_program_id: &Pubkey, _accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    match data.first() {
        Some(0) => msg!("Instruction: Ping"),
        _ => msg!("unknown instruction"),
    }
    Ok(())
}

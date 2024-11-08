use anchor_lang::prelude::*;

#[error_code]
pub enum WalletError {
    #[msg("Invalid EVM signature")]
    InvalidSignature,
    #[msg("Transaction replay detected")]
    ReplayDetected,
    #[msg("Invalid instruction sequence")]
    InvalidInstructionSequence,
    #[msg("Invalid action parameters")]
    InvalidActionParameters,
}

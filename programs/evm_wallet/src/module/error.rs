use anchor_lang::prelude::*;

#[error_code]
pub enum WalletError {
    #[msg("Invalid EVM signature")]
    InvalidSignature,
    #[msg("Transaction replay detected")]
    ReplayDetected,
    #[msg("Transaction too old - can't verify against recent history")]
    TransactionTooOld,
    #[msg("Invalid action parameters")]
    InvalidActionParameters,
}

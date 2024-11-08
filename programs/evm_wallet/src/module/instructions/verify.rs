use super::super::*;
use anchor_lang::prelude::*;
use anchor_lang::solana_program::secp256k1_program::ID as SECP256K1_PROGRAM_ID;
use solana_nostd_secp256k1_recover::secp256k1_recover;

use sha3::{Digest, Keccak256};
// Helper function to verify signatures
fn verify_eth_signature(
    message: &[u8; 32],
    signature: &[u8; 65],
    expected_address: &[u8; 20],
) -> std::result::Result<(), WalletError> {
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&signature[..64]);
    let recovery_id = signature[64];

    // Calculate recovery bit correctly:
    // The recovery_id in Ethereum signatures is 27 or 28
    // We need to convert this to a binary value (0 or 1)
    let is_odd = (recovery_id - 27) & 1 == 1;

    let pubkey =
        secp256k1_recover(message, is_odd, &sig).map_err(|_| WalletError::InvalidSignature)?;

    let mut hasher = Keccak256::new();
    hasher.update(&pubkey);
    let hash = hasher.finalize();
    let recovered_address = &hash[12..32];

    if recovered_address != expected_address {
        return Err(WalletError::InvalidSignature);
    }

    Ok(())
}
#[derive(Accounts)]
#[instruction(eth_address: [u8; 20])]
pub struct VerifySignature<'info> {
    #[account(
        init_if_needed,
        seeds = [
            WALLET_SEED_PREFIX,
            eth_address.as_ref()
        ],
        bump,
        space = WalletState::LEN,
        payer = payer
    )]
    pub wallet_state: Account<'info, WalletState>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
    /// CHECK:
    #[account(address = SECP256K1_PROGRAM_ID)]
    pub secp256k1_program: AccountInfo<'info>,
}

pub fn verify_signature(
    ctx: Context<VerifySignature>,
    eth_address: [u8; 20],
    message: VerifiableMessage,
    signature: [u8; 65],
) -> Result<()> {
    let wallet = &mut ctx.accounts.wallet_state;
    // Check nonce
    require!(
        message.nonce > wallet.nonce,
        WalletError::InvalidInstructionSequence
    );

    // Check signature replay
    require!(
        !wallet.has_signature(&signature),
        WalletError::ReplayDetected
    );
    // Get message hash
    let message_hash = message.get_eth_message()?;
    let message_hash: [u8; 32] = message_hash
        .try_into()
        .map_err(|_| WalletError::InvalidSignature)?;

    verify_eth_signature(&message_hash, &signature, &eth_address)?;

    // Initialize if needed
    if wallet.eth_address == [0u8; 20] {
        wallet.initialize(eth_address, ctx.bumps.wallet_state);
    }

    // Update state
    wallet.nonce = message.nonce;
    wallet.add_signature(signature);

    // Store verification result
    let ver_result = VerificationResult {
        message,
        eth_address,
    };

    anchor_lang::solana_program::program::set_return_data(&ver_result.try_to_vec()?);

    Ok(())
}

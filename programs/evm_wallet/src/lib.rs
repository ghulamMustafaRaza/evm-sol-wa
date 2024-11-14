mod module;
use {anchor_lang::prelude::*, module::*};

declare_id!("4RhFdtzGHv2tJz6MJ8vbyPZjhmLC79eCCDmTcXcokKSm");

#[program]
pub mod evm_wallet {
    use super::*;
    pub fn verify_signature(
        ctx: Context<VerifySignature>,
        eth_address: [u8; 20],
        message: VerifiableMessage,
        signature: [u8; 65],
    ) -> Result<()> {
        instructions::verify_signature(ctx, eth_address, message, signature)
    }
}

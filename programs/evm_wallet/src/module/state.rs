use super::*;
use anchor_lang::prelude::*;
use sha3::{Digest, Keccak256};

// #[account(zero_copy(unsafe))]
// #[repr(C)]
#[account]
#[derive(Default)]
pub struct WalletState {
    /// The Ethereum address that owns this wallet
    pub eth_address: [u8; 20],
    /// Current nonce for transaction ordering
    pub nonce: u64,
    /// Fixed array of recent signatures for replay protection
    pub recent_signatures: RecentTransactions,
    /// Current index in the signature array (circular buffer)
    pub current_index: u8,
    /// Number of valid signatures stored
    pub num_signatures: u8,
    /// Bump seed for PDA derivation
    pub bump: u8,
    /// Reserved for future use
    pub _padding: [u8; 5], // Align to 8 bytes
}
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct RecentTransactions {
    pub inner: [[u8; 65]; SIGNATURE_QUEUE_SIZE],
}
impl Default for RecentTransactions {
    fn default() -> Self {
        Self {
            inner: [[0; 65]; SIGNATURE_QUEUE_SIZE],
        }
    }
}

// Message structures remain AnchorSerialize/Deserialize since they're passed as instruction data
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct VerifiableMessage {
    pub nonce: u64,
    pub actions: Vec<Action>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub enum Action {
    Transfer {
        amount: u64,
        recipient: Pubkey,
        mint: Option<Pubkey>,
    },
}

impl WalletState {
    pub const LEN: usize = 8 + // discriminator
                          20 + // eth_address
                          8 +  // nonce
                          (65 * SIGNATURE_QUEUE_SIZE) + // fixed size signature array
                          1 +  // current_index
                          1 +  // num_signatures
                          1 +  // bump
                          5; // padding

    pub fn initialize(&mut self, eth_address: [u8; 20], bump: u8) {
        self.eth_address = eth_address;
        self.nonce = 0;
        self.current_index = 0;
        self.num_signatures = 0;
        self.bump = bump;
    }

    pub fn add_signature(&mut self, signature: [u8; 65]) {
        // Write to current index
        self.recent_signatures.inner[self.current_index as usize] = signature;

        // Update circular buffer index
        self.current_index = ((self.current_index as usize + 1) % SIGNATURE_QUEUE_SIZE) as u8;

        // Update number of valid signatures
        if self.num_signatures < SIGNATURE_QUEUE_SIZE as u8 {
            self.num_signatures += 1;
        }
    }

    pub fn has_signature(&self, signature: &[u8; 65]) -> bool {
        // Only check valid signatures in the buffer
        let num_to_check = self.num_signatures as usize;

        for i in 0..num_to_check {
            if self.recent_signatures.inner[i] == *signature {
                return true;
            }
        }
        false
    }
}

impl VerifiableMessage {
    pub fn to_string(&self) -> String {
        let mut output = String::new();

        // Use explicit \n instead of writeln!
        output.push_str("EVM Wallet Transaction\n");
        output.push_str(&format!("Nonce: {}\n", self.nonce));
        output.push_str("\n");
        output.push_str("Actions to perform:\n");

        for (i, action) in self.actions.iter().enumerate() {
            match action {
                Action::Transfer {
                    amount,
                    recipient,
                    mint,
                } => {
                    let token_type = match mint {
                        Some(mint_key) => format!("SPL Token (Mint: {})", mint_key),
                        None => "SOL".to_string(),
                    };

                    output.push_str(&format!(
                        "{}. Transfer {} {} to recipient {}\n",
                        i + 1,
                        amount,
                        token_type,
                        recipient
                    ));
                }
            }
        }

        output.push_str("\n");
        output.push_str("WARNING: Only sign this message if you trust the source and have verified the contents.");

        output
    }

    pub fn get_eth_message(&self) -> Result<Vec<u8>> {
        let mut hasher = Keccak256::new();
        let message_bytes = self.to_string().into_bytes();

        // Ethereum signed message prefix
        let prefix = b"\x19Ethereum Signed Message:\n";
        let message_len = message_bytes.len().to_string();

        hasher.update(prefix);
        hasher.update(message_len.as_bytes());
        hasher.update(&message_bytes);

        Ok(hasher.finalize().to_vec())
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct VerificationResult {
    pub message: VerifiableMessage,
    pub eth_address: [u8; 20],
}

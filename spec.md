# EVM-Solana Wallet Abstraction Technical Specification

## Overview
This document outlines the technical specification for a wallet abstraction system that enables EVM wallet holders to control Solana accounts through message signing. The system provides secure transaction execution with replay protection and specialized instruction handlers.

## Core Components

### 1. Wallet State PDA
- Stores last 20 transaction signatures in FIFO queue
- Maintains current nonce for beyond-FIFO validation
- Derived from EVM address
- Will act as user's abstracted wallet and will be used to sign transactions.

### 2. Message Structure
```rust
struct VerifiableMessage {
    nonce: u64,
    actions: Vec<Action>,
}

enum Action {
    Transfer {
        amount: u64,
        recipient: Pubkey,
        mint: Option<Pubkey>,  // None for SOL, Some(mint) for SPL tokens
    }
}
```

### 3. Transaction Structure
Each valid transaction consists of:
1. Verification instruction (mandatory first IX)
2. Action handler instruction(s)

## Instruction Specifications

### 1. Verification Instruction
```rust
#[program]
pub mod evm_wallet {
    #[instruction]
    pub fn verify_signature(
        ctx: Context<VerifySignature>,
        message: VerifiableMessage,
        signature: [u8; 65],  // r,s,v from EVM
    ) -> Result<()> {
        // Implementation details
    }
}

#[derive(Accounts)]
pub struct VerifySignature<'info> {
    #[account(mut)]
    pub wallet_state: Account<'info, WalletState>,
    pub system_program: Program<'info, System>,
}
```

### 2. Transfer Handler Instructions
```rust
#[program]
pub mod evm_wallet {
    #[instruction]
    pub fn execute_sol_transfer(
        ctx: Context<ExecuteTransfer>,
        amount: u64,
    ) -> Result<()> {
        // Implementation details
    }

    #[instruction]
    pub fn execute_token_transfer(
        ctx: Context<ExecuteTokenTransfer>,
        amount: u64,
    ) -> Result<()> {
        // Implementation details
    }
}
```

## Security Measures

### 1. Replay Protection
- FIFO queue of 20 recent transaction signatures
- Transactions with signatures in FIFO are rejected
- Transactions with nonce <= (current_nonce - FIFO_SIZE) are rejected
- Nonce increments with each successful transaction

### 2. Instruction Validation
- First instruction must be verification instruction
- Handler instructions verify they follow verification instruction using ix_sysvar
- Handlers validate calling context matches verified message

### 3. Message Signing
```
Message Format:
\x19Ethereum Signed Message:\n
<length>
<serialized VerifiableMessage>
```

## Implementation Flow

1. **Client Side**:
   - Construct VerifiableMessage
   - Serialize message with EIP-191 prefix
   - Sign with EVM wallet
   - Build Solana transaction with verify + handler instructions

2. **Verification Instruction**:
   - Recover EVM signer from signature
   - Validate nonce and FIFO status
   - Update wallet state
   - Store verified message in transaction context

3. **Handler Instructions**:
   - Verify they follow verification instruction
   - Execute specific action logic
   - Maintain atomic transaction properties

## Error Handling
Leveraging Anchor's error handling:
```rust
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
```

## Future Extensions
1. Additional Action types
2. Arbitrary CPI support
3. Multi-signature support
4. Account management features

## Development Phases

### Phase 1: Core Implementation
1. Basic PDA structure with FIFO
2. Verification instruction
3. SOL transfer handler

### Phase 2: Token Support
1. SPL token transfer handler
2. Token account management

### Phase 3: Advanced Features
1. Additional action types
2. Arbitrary instruction support
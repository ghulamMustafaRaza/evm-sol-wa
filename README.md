# EVM-Solana Wallet Abstraction

A secure bridge enabling EVM wallet holders to control Solana accounts through message signing, providing seamless cross-chain wallet management capabilities.

## Features

- **EVM Wallet Integration**: Control Solana accounts using your existing EVM wallet
- **Secure Transaction Execution**: Built-in replay protection with FIFO queue system
- **Native Asset Support**: Transfer SOL and SPL tokens
- **Message Verification**: EIP-191 compliant message signing and verification
- **Wallet Abstraction**: PDA-based wallet management

## Installation

```bash
# Clone the repository
git clone https://github.com/ghulamMustafaRaza/evm--sol_wallet_abstraction evm-solana-wallet
cd evm-solana-wallet

# Install dependencies
yarn install

# Build the program
anchor build

# Integration tests the program
anchor test

# Unit tests the program
cargo test
```

## Usage

### Prerequisites
- Solana CLI tools
- Anchor Framework
- Node.js environment
- An EVM wallet (e.g., MetaMask)

### Basic Example

```typescript
// Client-side code example will be provided after implementation
```

## Architecture

### Core Components

1. **Wallet State PDA**
   - Stores transaction history
   - Maintains nonce for replay protection
   - Derived from EVM address

2. **Message Structure**
   - Nonce-based verification
   - Support for multiple action types
   - Extendable for future features

3. **Transaction Flow**
   - Signature verification
   - Action execution
   - Atomic transaction guarantees

## Security

The system implements multiple security measures:

- **Replay Protection**: 20-transaction FIFO queue
- **Signature Verification**: EIP-191 compliant
- **Transaction Validation**: Strict instruction ordering
- **Atomic Execution**: All-or-nothing transaction guarantees

## Development

### Project Structure
```
├── programs/
│   └── evm-wallet/
│       ├── src/
│       └── Cargo.toml
├── app/
│   ├── src/
│   └── package.json
├── tests/
└── Anchor.toml
```

### Development Phases

1. **Phase 1**: Core Implementation
   - Basic PDA structure
   - Verification system
   - SOL transfers

2. **Phase 2**: Token Support
   - SPL token transfers
   - Token account management

3. **Phase 3**: Advanced Features
   - Additional action types
   - Arbitrary instruction support

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to your branch
5. Create a Pull Request

### Coding Standards

- Follow Rust formatting guidelines
- Write tests for new features
- Document public interfaces
- Update technical documentation

---

For detailed technical specifications, please refer to the [Technical Specification](./spec.md) document.
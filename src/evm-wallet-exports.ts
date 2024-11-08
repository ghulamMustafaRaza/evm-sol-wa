// Here we export some useful types and functions for interacting with the Anchor program.
import { AnchorProvider, Program } from '@coral-xyz/anchor'
import { PublicKey } from '@solana/web3.js'
import EvmWalletIDL from '../target/idl/evm_wallet.json'
import type { EvmWallet } from '../target/types/evm_wallet'

// Re-export the generated IDL and type
export { EvmWallet, EvmWalletIDL }

// The programId is imported from the program IDL.
export const EVM_WALLET_PROGRAM_ID = new PublicKey(EvmWalletIDL.address)

// This is a helper function to get the EvmWallet Anchor program.
export function getEvmWalletProgram(provider: AnchorProvider) {
  return new Program(EvmWalletIDL as EvmWallet, provider)
}
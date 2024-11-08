
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import { EthereumSigner } from "./utils/ethereum";
import { EvmWallet } from '../target/types/evm_wallet';
import { bs58 } from "@coral-xyz/anchor/dist/cjs/utils/bytes";


describe("evm-wallet", () => {
  const provider = anchor.AnchorProvider.env();
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.EvmWallet as Program<EvmWallet>;

  // Test Ethereum wallet
  const signer = EthereumSigner.random();

  let walletStatePda: PublicKey;
  let walletBump: number;

  beforeAll(() => {
    // Find PDA for wallet state
    const ethAddress = Buffer.from(signer.getAddress().slice(2), 'hex');
    [walletStatePda, walletBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("evm_wallet"), ethAddress],
      program.programId
    );
  });

  it("Can verify signature and create wallet", async () => {
    // Create test message
    const recipient = Keypair.generate().publicKey;
    const message = {
      nonce: new anchor.BN(1),
      actions: [{
        transfer: {
          amount: new anchor.BN(1_000_000_000),
          recipient: recipient,
          mint: null,
        }
      }]
    };

    // Sign message with Ethereum wallet
    const signature = await signer.signMessage(message);
    const sigBytes = Buffer.from(signature.slice(2), 'hex');

    // Convert Ethereum address to bytes
    const ethAddress = Buffer.from(signer.getAddress().slice(2), 'hex');
    try {
      await program.methods
        .verifySignature(Array.from(ethAddress), message, Array.from(sigBytes))
        .accounts({
          payer: provider.wallet.publicKey,
        })
        .rpc();

      // Verify wallet state
      const walletState = await program.account.walletState.fetch(walletStatePda);
      expect(Buffer.from(walletState.ethAddress).toString("hex")).toBe(Buffer.from(ethAddress).toString("hex"));
      expect(walletState.nonce.toString()).toEqual("1");
    } catch (err) {
      console.error("Error:", err);
      throw err;
    }
  });


  it("Prevents replay attacks", async () => {
    // Use the same message and signature from previous test
    const recipient = Keypair.generate().publicKey;
    const message = {
      nonce: new anchor.BN(1),  // Same nonce
      actions: [{
        transfer: {
          amount: new anchor.BN(1_000_000_000),
          recipient: recipient,
          mint: null,
        }
      }]
    };

    const signature = await signer.signMessage(message);
    const sigBytes = Buffer.from(signature.slice(2), 'hex');
    const ethAddress = Buffer.from(signer.getAddress().slice(2), 'hex');

    // Attempt to replay the same signature
    await expect(
      program.methods
        .verifySignature(Array.from(ethAddress), message, Array.from(sigBytes))
        .accounts({
          payer: provider.wallet.publicKey,
        })
        .rpc()
    ).rejects.toThrow(/ReplayDetected/);

    // Verify state hasn't changed
    const walletState = await program.account.walletState.fetch(walletStatePda);
    expect(walletState.nonce.toString()).toBe("1");
  });

  it("Validates nonce ordering", async () => {
    // Create message with lower nonce
    const recipient = Keypair.generate().publicKey;
    const message = {
      nonce: new anchor.BN(0),  // Lower than current nonce (1)
      actions: [{
        transfer: {
          amount: new anchor.BN(1_000_000_000),
          recipient: recipient,
          mint: null,
        }
      }]
    };

    const signature = await signer.signMessage(message);
    const sigBytes = Buffer.from(signature.slice(2), 'hex');
    const ethAddress = Buffer.from(signer.getAddress().slice(2), 'hex');

    // Attempt to submit transaction with lower nonce
    await expect(
      program.methods
        .verifySignature(Array.from(ethAddress), message, Array.from(sigBytes))
        .accounts({
          payer: provider.wallet.publicKey,
        })
        .rpc()
    ).rejects.toThrow(/InvalidInstructionSequence/);

    // Verify nonce hasn't changed
    const walletState = await program.account.walletState.fetch(walletStatePda);
    expect(walletState.nonce.toString()).toBe("1");
  });

  it("Accepts valid higher nonce", async () => {
    // Create message with higher nonce
    const recipient = Keypair.generate().publicKey;
    const message = {
      nonce: new anchor.BN(2),  // Higher than current nonce (1)
      actions: [{
        transfer: {
          amount: new anchor.BN(1_000_000_000),
          recipient: recipient,
          mint: null,
        }
      }]
    };

    const signature = await signer.signMessage(message);
    const sigBytes = Buffer.from(signature.slice(2), 'hex');
    const ethAddress = Buffer.from(signer.getAddress().slice(2), 'hex');

    await program.methods
      .verifySignature(Array.from(ethAddress), message, Array.from(sigBytes))
      .accounts({
        payer: provider.wallet.publicKey,
      })
      .rpc();

    // Verify nonce was updated
    const walletState = await program.account.walletState.fetch(walletStatePda);
    expect(walletState.nonce.toString()).toBe("2");
  });
});
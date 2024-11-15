import { Connection, PublicKey, ComputeBudgetProgram, Transaction, Keypair, VersionedTransaction, LAMPORTS_PER_SOL } from '@solana/web3.js';
import { AnchorProvider, Program, web3 } from '@coral-xyz/anchor';
import { ethers, BrowserProvider } from 'ethers';
import { EthereumSigner, VerifiableMessage } from '@/utils/ethereum';
import { Buffer } from 'buffer';
import { EVM_WALLET_PROGRAM_ID, EvmWallet, getEvmWalletProgram } from '@/evm-wallet-exports';
import { BN } from 'bn.js';

// Your program ID
const PROGRAM_ID = EVM_WALLET_PROGRAM_ID;
const SOLANA_NETWORK = 'http://localhost:8899';

class EvmSolanaBridge {
    private connection: Connection;
    private metamaskSigner: ethers.JsonRpcSigner | null = null;
    // We'll use a static keypair as payer - in production you might want to manage this differently
    private payerKeypair: Keypair;
    private program: Program<EvmWallet>;
    constructor() {
        this.connection = new Connection(SOLANA_NETWORK);
        // Generate a new keypair for paying transaction fees
        this.payerKeypair = Keypair.generate();

        // Create provider and program
        const provider = new AnchorProvider(
            this.connection,
            {
                publicKey: this.payerKeypair.publicKey,
                signTransaction: async <T extends Transaction | VersionedTransaction>(tx: T): Promise<T> => {
                    if ("version" in tx) {
                        tx.sign([this.payerKeypair]);
                    } else {
                        tx.partialSign(this.payerKeypair);
                    }
                    return tx;
                },
                signAllTransactions: async <T extends Transaction | VersionedTransaction>(txs: T[]): Promise<T[]> => {
                    txs.forEach(tx => {
                        if ("version" in tx) {
                            tx.sign([this.payerKeypair]);
                        } else {
                            tx.partialSign(this.payerKeypair);
                        }
                    });
                    return txs;
                }
            },
            { commitment: 'confirmed' }
        );

        // Initialize program
        this.program = getEvmWalletProgram(provider);

        this.setupEventListeners();
    }

    private setupEventListeners() {
        document.getElementById('connectMetamask')?.addEventListener('click', () => this.connectMetamask());
        document.getElementById('sendTransaction')?.addEventListener('click', () => this.sendTransaction());
    }

    private async connectMetamask() {
        try {
            if (!(window as any).ethereum) {
                throw new Error("MetaMask is not installed!");
            }
            const provider = new BrowserProvider((window as any).ethereum);
            this.metamaskSigner = await provider.getSigner();
            const address = await this.metamaskSigner.getAddress();
            this.showStatus('MetaMask connected: ' + address.slice(0, 6) + '...', 'success');
            this.updateButtonStates();

            // Request airdrop for the payer if on devnet/testnet
            const airdropSignature = await this.connection.requestAirdrop(
                this.payerKeypair.publicKey,
                web3.LAMPORTS_PER_SOL // 1 SOL
            );
            await this.connection.confirmTransaction(airdropSignature);

        } catch (err: any) {
            this.showStatus('Failed to connect MetaMask: ' + err.message, 'error');
        }
    }

    private async sendTransaction() {
        try {
            if (!this.metamaskSigner) {
                throw new Error('Please connect MetaMask first');
            }

            const amountInput = document.getElementById('amount') as HTMLInputElement;
            const recipientInput = document.getElementById('recipient') as HTMLInputElement;
            const amount = amountInput.value;
            const recipient = recipientInput.value;

            if (!amount || !recipient) {
                throw new Error('Please fill in all fields');
            }

            this.showStatus('Preparing transaction...', 'success');

            const ethAddress = await this.metamaskSigner.getAddress();
            const ethAddressBytes = Buffer.from(ethAddress.slice(2), 'hex');

            // Find PDA
            const [walletStatePda] = PublicKey.findProgramAddressSync(
                [Buffer.from("evm_wallet"), ethAddressBytes],
                PROGRAM_ID
            );
            const state = await this.program.account.walletState.fetch(walletStatePda, "processed").catch(() => ({ txnCount: 0 }));

            // Create message
            const message: VerifiableMessage = {
                lastKnownTxn: state.txnCount,
                actions: [{
                    transfer: {
                        amount: new BN(amount).mul(new BN(LAMPORTS_PER_SOL)), // Convert to lamports
                        recipient: new PublicKey(recipient),
                        mint: null,
                    }
                }]
            };

            const signer = new EthereumSigner(this.metamaskSigner as any);
            const signature = await signer.signMessage(message);
            const sigBytes = Buffer.from(signature.slice(2), 'hex');

            this.showStatus('Building Solana transaction...', 'success');

            // Set compute budget
            const computeIx = ComputeBudgetProgram.setComputeUnitLimit({
                units: 400_000
            });

            // Send transaction
            await this.program.methods
                .verifySignature(
                    Array.from(ethAddressBytes),
                    message,
                    Array.from(sigBytes)
                )
                .accounts({
                    payer: this.payerKeypair.publicKey,
                })
                .preInstructions([computeIx])
                .rpc();

            this.showStatus('Transaction successful!', 'success');
        } catch (err: any) {
            this.showStatus('Transaction failed: ' + err.message, 'error');
            console.error(err);
        }
    }

    private showStatus(message: string, type: 'success' | 'error') {
        const status = document.getElementById('status');
        if (status) {
            status.textContent = message;
            status.style.display = 'block';
            status.className = type;
        }
    }

    private updateButtonStates() {
        const sendBtn: HTMLButtonElement = document.getElementById('sendTransaction') as any;
        if (sendBtn) {
            sendBtn.disabled = !this.metamaskSigner;
        }
    }
}

// Initialize the app
window.addEventListener('load', () => {
    new EvmSolanaBridge();
});
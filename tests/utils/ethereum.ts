import { ethers, SigningKey } from "ethers";
import { PublicKey } from "@solana/web3.js";
import { BN } from "@coral-xyz/anchor";

export interface Action {
    transfer: {
        amount: BN;
        recipient: PublicKey;
        mint: PublicKey | null;
    };
}

export interface VerifiableMessage {
    nonce: number;
    actions: Action[];
}

export class EthereumSigner {
    constructor(private wallet: ethers.BaseWallet) { }
    static fromKey(privateKey: string | SigningKey) {
        return new EthereumSigner(new ethers.Wallet(privateKey))
    }
    static random() {
        return new EthereumSigner(ethers.Wallet.createRandom())
    }

    public getAddress(): string {
        return this.wallet.address;
    }

    public async signMessage(message: VerifiableMessage): Promise<string> {

        const messageString = this.formatMessage(message);
        const sig = await this.wallet.signMessage(messageString);
        return sig;
    }

    private formatMessage(message: VerifiableMessage): string {
        let output = `EVM Wallet Transaction\n`;
        output += `Nonce: ${message.nonce.toString()}\n\n`;
        output += `Actions to perform:\n`;

        message.actions.forEach((action, i) => {
            if ('transfer' in action) {
                const transfer = action.transfer;
                const tokenType = transfer.mint ? `SPL Token (Mint: ${transfer.mint})` : 'SOL';
                output += `${i + 1}. Transfer ${transfer.amount} ${tokenType} to recipient ${transfer.recipient}\n`;
            }
        });

        output += `\nWARNING: Only sign this message if you trust the source and have verified the contents.`;
        return output;
    }
}
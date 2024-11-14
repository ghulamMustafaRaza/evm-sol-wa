import { ethers, getBytes, hashMessage, SigningKey } from "ethers";
import fs from "fs";

async function generateTestVectors() {
  // Create a random wallet for testing
  const wallet = new ethers.Wallet(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  );
  console.log("Wallet address:", wallet.address);

  // Create test message
  const message = {
    nonce: 1,
    actions: [
      {
        transfer: {
          amount: 1_000_000_000,
          recipient: "11111111111111111111111111111111",
          mint: null,
        },
      },
    ],
  };

  // Format message as string
  const messageString =
    `EVM Wallet Transaction\n` +
    `Nonce: ${message.nonce}\n\n` +
    `Actions to perform:\n` +
    `1. Transfer ${message.actions[0].transfer.amount} SOL to recipient ${message.actions[0].transfer.recipient}\n\n` +
    `WARNING: Only sign this message if you trust the source and have verified the contents.`;

  console.log("\nMessage to sign:", messageString);

  // Sign message
  const signature = await wallet.signMessage(messageString);
  console.log("\nSignature:", signature);

  // Get the raw bytes
  const sigBytes = getBytes(signature);
  console.log("\nSignature bytes:", Buffer.from(sigBytes).toString("hex"));

  // Get message hash (how ethers.js hashes it)
  const messageHash = hashMessage(messageString);
  console.log("\nMessage hash:", messageHash);
  console.log(
    "Message hash bytes:",
    Buffer.from(getBytes(messageHash)).toString("hex")
  );

  // Write test vector
  const testVector = {
    private_key: wallet.privateKey.slice(2),
    address: wallet.address.slice(2).toLowerCase(),
    message_string: messageString,
    message_hash: messageHash.slice(2).toLowerCase(),
    signature: signature.slice(2).toLowerCase(),
  };

  fs.writeFileSync("test_vector.json", JSON.stringify(testVector, null, 2));
  console.log("\nTest vector written to test_vector.json");
}

generateTestVectors().catch(console.error);

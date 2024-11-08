#[cfg(test)]
mod tests {
    use super::super::*;
    #[test]
    fn test_message_formatting() {
        use anchor_lang::prelude::Pubkey;

        let message = VerifiableMessage {
            nonce: 1,
            actions: vec![Action::Transfer {
                amount: 1_000_000_000,
                recipient: Pubkey::new_unique(),
                mint: None,
            }],
        };

        let formatted = message.to_string();
        assert!(formatted.contains("Nonce: 1"));
        assert!(formatted.contains("Transfer"));
        assert!(formatted.contains("SOL"));
    }

    #[test]
    fn test_recent_transactions() {
        let mut recent = RecentTransactions::default();
        let sig1 = [1u8; 65];
        let sig2 = [2u8; 65];

        // Test indexing
        recent.inner[0] = sig1;
        recent.inner[1] = sig2;

        assert_eq!(recent.inner[0], sig1);
        assert_eq!(recent.inner[1], sig2);
    }

    #[test]
    fn test_wallet_state() {
        let mut state = WalletState::default();
        let test_sig = [1u8; 65];
        let test_address = [2u8; 20];

        state.initialize(test_address, 1);
        assert_eq!(state.nonce, 0);
        assert_eq!(state.eth_address, test_address);
        assert_eq!(state.current_index, 0);
        assert_eq!(state.num_signatures, 0);

        // Test signature operations
        assert!(!state.has_signature(&test_sig));
        state.add_signature(test_sig);
        assert!(state.has_signature(&test_sig));
        assert_eq!(state.current_index, 1);
        assert_eq!(state.num_signatures, 1);
    }

    #[test]
    fn test_circular_buffer() {
        let mut state = WalletState::default();

        // Fill buffer
        for i in 0..SIGNATURE_QUEUE_SIZE {
            let sig = [i as u8; 65];
            state.add_signature(sig);
            assert!(state.has_signature(&sig));
        }

        // Verify circular behavior
        assert_eq!(state.current_index, 0);
        assert_eq!(state.num_signatures as usize, SIGNATURE_QUEUE_SIZE);

        // Add one more and verify oldest is overwritten
        let new_sig = [100u8; 65];
        state.add_signature(new_sig);
        assert!(state.has_signature(&new_sig));
        assert!(!state.has_signature(&[0u8; 65])); // First signature should be overwritten
    }
}

#[cfg(test)]
mod sig_tests {
    use std::result;

    use crate::*;

    use hex_literal::hex;
    use sha3::{Digest, Keccak256};
    // {
    //   "private_key": "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    //   "address": "f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    //   "message_string": "EVM Wallet Transaction\nNonce: 1\n\nActions to perform:\n1. Transfer 1000000000 SOL to recipient 9aE84EeC56B16C81533292111ED945433f586012\n\nWARNING: Only sign this message if you trust the source and have verified the contents.",
    //   "message_hash": "fb50c85a34304b60bb766fe43de1eb4fb8bfb562e94887225b25cd1313d2f636",
    //   "signature": "03ea98e90b77c799cb0f6065c2eda75713e06c8a4a26907f1777c8a1db9cd1361670128f1b7bc3315d8bac0a75dae074d475613bed0c5d4c26786b82129c7d3f1c"
    // }
    // Known test vector 1 - from Ethereum transaction
    // const TEST_VECTOR_1: TestVector = TestVector {
    //     private_key: hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
    //     message: hex!("fb50c85a34304b60bb766fe43de1eb4fb8bfb562e94887225b25cd1313d2f636"),
    //     signature: hex!(
    //         "03ea98e90b77c799cb0f6065c2eda75713e06c8a4a26907f1777c8a1db9cd1361670128f1b7bc3315d8bac0a75dae074d475613bed0c5d4c26786b82129c7d3f1c"
    //     ),
    //     address: hex!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
    // };
    // {
    //   "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    //   "address": "fcad0b19bb29d4674531d6f115237e16afce377c",
    //   "message_string": "EVM Wallet Transaction\nNonce: 1\n\nActions to perform:\n1. Transfer 1000000000 SOL to recipient 9aE84EeC56B16C81533292111ED945433f586012\n\nWARNING: Only sign this message if you trust the source and have verified the contents.",
    //   "message_hash": "fb50c85a34304b60bb766fe43de1eb4fb8bfb562e94887225b25cd1313d2f636",
    //   "signature": "327470b41867b4d40620fef3ed4857ec30ca49eab7203aa66f288681a4d7a0fc56b4526edaa25a95fdb3a95c881c81db3f01f7847aa6f47c10ef2bb8f7db7f361c"
    // }
    // Known test vector 2 - from ethers.js
    const TEST_VECTOR: TestVector = TestVector {
        private_key: hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        message: hex!("582df94f2f1fa406c7101d2c479fb9a6fbe87d654ec9af4fc494761452d22415"),
        signature: hex!(
            "b1385e207ed3c901d0e8e13843d5b81b36cd057de35c9c224f29701932eed54928e4482309eafe4d8a53599dc57870f2543b5f1992e7678386f4e27234b393921b"
        ),
        message_raw: "EVM Wallet Transaction\nNonce: 1\n\nActions to perform:\n1. Transfer 1000000000 SOL to recipient 11111111111111111111111111111111\n\nWARNING: Only sign this message if you trust the source and have verified the contents.",
        address: hex!("fcad0b19bb29d4674531d6f115237e16afce377c"),
    };

    // Struct to hold test vectors
    struct TestVector {
        private_key: [u8; 32],
        message: [u8; 32],
        message_raw: &'static str,
        signature: [u8; 65],
        address: [u8; 20],
    }

    // #[test]
    // fn test_vector_1() {
    //     test_signature_verification(&TEST_VECTOR_1);
    // }

    // #[test]
    // fn test_vector_2() {
    //     test_signature_verification(&TEST_VECTOR_2);
    // }

    fn test_signature_verification(vector: &TestVector) {
        println!("\nTesting with vector:");
        println!("Private key: {}", hex::encode(&vector.private_key));
        println!("Message: {}", hex::encode(&vector.message));
        println!("Signature: {}", hex::encode(&vector.signature));
        println!("Expected address: {}", hex::encode(&vector.address));
        verify_eth_signature(&vector.message, &vector.signature, &vector.address).unwrap()

        // assert_eq!(
        //     recovered_address,
        //     &vector.address,
        //     "Address mismatch!\nExpected: {}\nGot: {}",
        //     hex::encode(&vector.address),
        //     hex::encode(recovered_address)
        // );
    }

    // Helper function to verify signatures
    fn verify_eth_signature(
        message: &[u8; 32],
        signature: &[u8; 65],
        expected_address: &[u8; 20],
    ) -> result::Result<(), WalletError> {
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&signature[..64]);
        let recovery_id = signature[64];
        let is_odd = (recovery_id - 27) & 1 == 1;

        let pubkey = solana_nostd_secp256k1_recover::secp256k1_recover(message, is_odd, &sig)
            .map_err(|_| WalletError::InvalidSignature)?;

        let mut hasher = Keccak256::new();
        hasher.update(&pubkey);
        let hash = hasher.finalize();
        let recovered_address = &hash[12..32];

        if recovered_address != expected_address {
            return Err(WalletError::InvalidSignature);
        }

        Ok(())
    }
    #[test]
    fn test_with_ethers() {
        // Create the exact same message as in JS
        let message = VerifiableMessage {
            nonce: 1,
            actions: vec![Action::Transfer {
                amount: 1_000_000_000,
                recipient: Pubkey::default(),
                mint: None,
            }],
        };

        let formatted = message.to_string();
        println!("{}", formatted);
        // Expected format from ethers.js

        assert_eq!(formatted, TEST_VECTOR.message_raw);

        let hash = hex::encode(message.get_eth_message().unwrap());
        println!("{}", hash);
        // Expected format from ethers.js

        assert_eq!(hash, hex::encode(TEST_VECTOR.message));

        test_signature_verification(&TEST_VECTOR)
    }
}

/**
 * Program IDL in camelCase format in order to be used in JS/TS.
 *
 * Note that this is only a type helper and is not the actual IDL. The original
 * IDL can be found at `target/idl/evm_wallet.json`.
 */
export type EvmWallet = {
  "address": "6z68wfurCMYkZG51s1Et9BJEd9nJGUusjHXNt4dGbNNF",
  "metadata": {
    "name": "evmWallet",
    "version": "0.1.0",
    "spec": "0.1.0",
    "description": "Created with Anchor"
  },
  "instructions": [
    {
      "name": "verifySignature",
      "discriminator": [
        91,
        139,
        24,
        69,
        251,
        162,
        245,
        112
      ],
      "accounts": [
        {
          "name": "walletState",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  101,
                  118,
                  109,
                  95,
                  119,
                  97,
                  108,
                  108,
                  101,
                  116
                ]
              },
              {
                "kind": "arg",
                "path": "ethAddress"
              }
            ]
          }
        },
        {
          "name": "payer",
          "writable": true,
          "signer": true
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        },
        {
          "name": "secp256k1Program",
          "address": "KeccakSecp256k11111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "ethAddress",
          "type": {
            "array": [
              "u8",
              20
            ]
          }
        },
        {
          "name": "message",
          "type": {
            "defined": {
              "name": "verifiableMessage"
            }
          }
        },
        {
          "name": "signature",
          "type": {
            "array": [
              "u8",
              65
            ]
          }
        }
      ]
    }
  ],
  "accounts": [
    {
      "name": "walletState",
      "discriminator": [
        126,
        186,
        0,
        158,
        92,
        223,
        167,
        68
      ]
    }
  ],
  "errors": [
    {
      "code": 6000,
      "name": "invalidSignature",
      "msg": "Invalid EVM signature"
    },
    {
      "code": 6001,
      "name": "replayDetected",
      "msg": "Transaction replay detected"
    },
    {
      "code": 6002,
      "name": "invalidInstructionSequence",
      "msg": "Invalid instruction sequence"
    },
    {
      "code": 6003,
      "name": "invalidActionParameters",
      "msg": "Invalid action parameters"
    }
  ],
  "types": [
    {
      "name": "action",
      "type": {
        "kind": "enum",
        "variants": [
          {
            "name": "transfer",
            "fields": [
              {
                "name": "amount",
                "type": "u64"
              },
              {
                "name": "recipient",
                "type": "pubkey"
              },
              {
                "name": "mint",
                "type": {
                  "option": "pubkey"
                }
              }
            ]
          }
        ]
      }
    },
    {
      "name": "recentTransactions",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "inner",
            "type": {
              "array": [
                {
                  "array": [
                    "u8",
                    65
                  ]
                },
                20
              ]
            }
          }
        ]
      }
    },
    {
      "name": "verifiableMessage",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "nonce",
            "type": "u32"
          },
          {
            "name": "actions",
            "type": {
              "vec": {
                "defined": {
                  "name": "action"
                }
              }
            }
          }
        ]
      }
    },
    {
      "name": "walletState",
      "serialization": "bytemuckunsafe",
      "repr": {
        "kind": "c"
      },
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "ethAddress",
            "docs": [
              "The Ethereum address that owns this wallet"
            ],
            "type": {
              "array": [
                "u8",
                20
              ]
            }
          },
          {
            "name": "nonce",
            "docs": [
              "Current nonce for transaction ordering"
            ],
            "type": "u32"
          },
          {
            "name": "recentSignatures",
            "docs": [
              "Fixed array of recent signatures for replay protection"
            ],
            "type": {
              "defined": {
                "name": "recentTransactions"
              }
            }
          },
          {
            "name": "currentIndex",
            "docs": [
              "Current index in the signature array (circular buffer)"
            ],
            "type": "u8"
          },
          {
            "name": "numSignatures",
            "docs": [
              "Number of valid signatures stored"
            ],
            "type": "u8"
          },
          {
            "name": "bump",
            "docs": [
              "Bump seed for PDA derivation"
            ],
            "type": "u8"
          }
        ]
      }
    }
  ]
};

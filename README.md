# Crossed - Meta-Transaction Relay Contract

A Clarity smart contract that enables meta-transactions on the Stacks blockchain through a relay system.

## Features

- **Nonce Management**
  - Tracks transaction counts per user
  - Prevents replay attacks
  - Supports nonce initialization and queries

- **Multiple Relay Methods**
  - `relay-call`: Secure relay using secp256k1 signature verification
  - `relay-call-simple`: Simplified relay with hash verification
  - `relay-call-direct`: Direct calling method for transaction originators

- **Read Operations**
  - Get current nonce
  - Get next expected nonce
  - Check nonce initialization status
  - Generate message hashes

## Error Handling

| Code | Description |
|------|-------------|
| `ERR-ALREADY-INITIALIZED` | User nonce already exists |
| `ERR-INVALID-NONCE` | Incorrect nonce provided |
| `ERR-NONCE-NOT-FOUND` | Nonce not initialized |
| `ERR-INVALID-SIGNATURE` | Signature verification failed |
| `ERR-INVALID-CALL-DATA` | Invalid or empty call data |
| `ERR-UNAUTHORIZED` | Unauthorized access attempt |

## Security Features

- Cryptographic signature verification
- Sequential nonce tracking
- Input validation
- Hash-based message verification

## Usage

```clarity
;; Initialize a user's nonce
(initialize-nonce tx-sender)

;; Execute a relay transaction
(relay-call 
    signer-principal
    nonce
    call-data
    signature)

;; Check current nonce
(get-nonce user-principal)
```

## Technical Requirements

- Stacks blockchain
- Support for secp256k1 signature verification
- Buffer support up to 128 bytes for call data
- 65-byte signature buffer support

## File Location
crossed.clar

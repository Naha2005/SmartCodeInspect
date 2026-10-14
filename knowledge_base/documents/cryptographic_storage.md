# OWASP Cryptographic Storage Cheat Sheet

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
Retrieved: 2026-10-11
Author: OWASP Cheat Sheet Series Team

## Introduction
The purpose of this cheat sheet is to provide developers with a simple checklist to protect sensitive data at rest and ensure proper cryptographic controls are implemented across their applications.

## Broken and Insecure Algorithms to Avoid
Do not use legacy, collision-vulnerable, or deprecated cryptographic algorithms:
- **Broken Hashing Algorithms:** MD5, SHA-1, MD4, RIPEMD. Practical collision attacks exist against MD5 and SHA-1 that allow attackers to forge digital signatures and generate identical hashes for different contents.
- **Broken Symmetric Ciphers:** DES, Triple DES (3DES), RC4, Blowfish.
- **Insecure Modes of Operation:** Electronic Codebook (ECB) mode must never be used because identical plaintext blocks encrypt to identical ciphertext blocks, preserving structural data patterns.

## Recommended Strong Cryptographic Algorithms
- **Cryptographic Hashes (Integrity & Signatures):** SHA-256, SHA-384, SHA-512, or SHA-3 family.
- **Password Storage:** Never use plain cryptographic hashes (like SHA-256 alone) for passwords. Always use adaptive, memory-hard key derivation functions: Argon2id (recommended), bcrypt, scrypt, or PBKDF2 with high iteration counts (minimum 600,000 iterations for HMAC-SHA256).
- **Symmetric Encryption:** AES-GCM (Galois/Counter Mode) with 256-bit keys or ChaCha20-Poly1305, providing authenticated encryption with associated data (AEAD).

## Key Management and Secret Storage
- Never hardcode cryptographic keys, secret tokens, or API passwords in source code.
- Keys must be generated using cryptographically secure pseudorandom number generators (CSPRNG), such as Python's `secrets` module or Java's `SecureRandom`.
- Secrets should be externalized into secure key management systems (e.g., AWS KMS, HashiCorp Vault) or system environment variables.

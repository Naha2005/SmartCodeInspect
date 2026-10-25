# OWASP Cryptographic Storage & Encryption Cheat Sheet (2026 Edition)

Source: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
Retrieved: 2026-10-25
Author: OWASP Cheat Sheet Series Global Security Committee
Status: Active Standard (2026 Revision)
Classification: CWE-311 (Missing Encryption), CWE-312 (Cleartext Storage), CWE-327 (Broken Crypto Algorithms), CWE-328 (Weak Hashes)

---

## 1. Executive Summary & Threat Architecture
Data at rest (stored within relational databases, NoSQL stores, distributed file systems, cloud object storage, backups, and cache tiers) represents an organization's highest-value asset and most vulnerable attack surface. A failure in cryptographic controls allows unauthorized internal actors or external adversaries who compromise infrastructure to exfiltrate bulk customer records, intellectual property, financial accounts, and personal identifying information (PII).

Cryptographic storage security requires more than merely running an encryption algorithm. It encompasses:
1. **Selecting Mathematically Sound Algorithms & Modes**: Employing modern Authenticated Encryption with Associated Data (AEAD) ciphers.
2. **Strict Nonce & Initialization Vector (IV) Hygiene**: Guaranteeing that IVs are uniquely generated per encryption operation to prevent key leakage.
3. **Comprehensive Key Lifecycle Management**: Isolating master keys via Hardware Security Modules (HSM) or Key Management Systems (KMS), enforcing envelope encryption, and facilitating automated key rotation.
4. **Data Minimization & Segregation**: Storing only necessary sensitive data and segregating encrypted payloads from the cryptographic keys required to decrypt them.

---

## 2. Insecure, Deprecated, and Prohibited Cryptographic Primitives

Applications in 2026 must actively audit and purge legacy ciphers and insecure modes of operation:

### 2.1 Deprecated Hash Functions
- **MD5 (CWE-328)**: Completely broken by practical collision attacks. Colliding X.509 certificates and executables can be generated in fractions of a second.
- **SHA-1 (CWE-328)**: Broken by the SHAttered and Shambles collision attacks. Disallowed by NIST, ISO, and PCI-DSS for signatures and integrity verifications.
- **MD4, RIPEMD, SHA-0**: Cryptographically obsolete.

### 2.2 Prohibited Symmetric Ciphers
- **DES (Data Encryption Standard)**: 56-bit key space brute-forced in hours by modern compute clusters.
- **Triple DES (3DES / TDEA)**: Suffers from the 64-bit block Sweet32 collision attack (CVE-2016-2183), allowing birthday-bound ciphertext recovery in high-volume traffic. Officially retired by NIST.
- **RC4 (Rivest Cipher 4 / ARC4)**: Stream cipher with severe keystream statistical biases, enabling plaintext recovery in TLS and WPA/WEP protocols.
- **Blowfish**: 64-bit block size vulnerable to Sweet32 block collision attacks.

### 2.3 Prohibited Modes of Operation
- **Electronic Codebook (ECB) Mode (e.g., `AES/ECB/PKCS5Padding`)**:
  Encrypts identical 16-byte plaintext blocks into identical ciphertext blocks. Preserves data patterns and structural relationships (the famous "ECB Penguin" visual leakage). Provides zero semantic security.
- **Cipher Block Chaining (CBC) without Integrity Authentication**:
  Prone to Padding Oracle Attacks (e.g., POODLE, Lucky Thirteen, Vaudenay's attack). Attackers intercept ciphertexts, modify bytes, and analyze decryption error messages or timing differences to recover the entire plaintext byte by byte.

---

## 3. Approved Modern Cryptographic Standards (2026 Guidelines)

| Purpose | Approved Standard | Minimum Key / Work Factor | Security Guarantees |
|---|---|---|---|
| **Symmetric Bulk Encryption (AEAD)** | AES-GCM (Galois/Counter Mode) | 256 bits (AES-256) | Confidentiality + Authenticity + Associated Data |
| **Symmetric Bulk Encryption (AEAD)** | ChaCha20-Poly1305 (RFC 8439) | 256 bits | High-speed software cipher resistant to timing side-channels |
| **Cryptographic Message Digest** | SHA-256, SHA-384, SHA-512, SHA-3 | 256 bits minimum digest | Preimage, Second-Preimage, and Collision Resistance |
| **High-Throughput Integrity Hash** | BLAKE3 | 256 bits | Parallelized Merkle-tree hashing with exceptional speed |
| **Password Storage / KDF** | Argon2id | 64 MB RAM, 3 passes, $p=4$ | Adaptive, memory-hard resistance against GPU/ASIC clusters |
| **Key Derivation Function (KDF)** | HKDF (RFC 5869 with SHA-256/512) | 256-bit pseudorandom key | Extracts and expands high-entropy cryptographic keys |
| **Asymmetric Key Exchange / Signature** | Ed25519 (EdDSA / RFC 8032) | 256-bit curve | Fast, constant-time, collision-resistant digital signatures |
| **Asymmetric Key Exchange / Signature** | RSA-OAEP / RSA-PSS | 4096-bit key length | Secure padding against Bleichenbacher and padding oracle attacks |

---

## 4. Key Management Architecture & Envelope Encryption

### 4.1 The Threat of Hardcoded and Colocated Keys
Storing encryption keys in source repositories, configuration files (`application.properties`, `.env`), or adjacent database tables nullifies encryption. A single directory traversal or repository leak completely compromises the protected data.

### 4.2 Envelope Encryption Architecture
Envelope encryption separates bulk data encryption from key protection:

```
[ Sensitive Plaintext Data ]
            │
            ▼
┌────────────────────────────────────────┐
│ Encrypt with Data Encryption Key (DEK) │ ──> [ Ciphertext Data at Rest ]
│ using AES-256-GCM                      │
└────────────────────────────────────────┘
            ▲
            │ (Generated per record)
    [ Ephemeral DEK ]
            │
            ▼
┌────────────────────────────────────────┐
│ Encrypt DEK with Master Key (KEK)      │ ──> [ Encrypted DEK ]
│ inside Hardware HSM / Cloud KMS        │     (Stored alongside Ciphertext)
└────────────────────────────────────────┘
            ▲
            │
    [ Root KEK inside HSM ]
    (Never leaves secure hardware)
```

1. **Root Key (Key Encryption Key - KEK)**: Resides exclusively within a FIPS 140-3 Level 3 Hardware Security Module (HSM) or managed Cloud KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault). The KEK never leaves the hardware boundary.
2. **Data Encryption Key (DEK)**: Generated freshly in memory for each record, session, or partition using a CSPRNG.
3. **Envelope Storage**: The data is encrypted with the DEK. The DEK is encrypted with the KEK. The encrypted data and the encrypted DEK are stored together. To decrypt, the application passes only the encrypted DEK to the KMS to obtain the plaintext DEK in volatile memory.

---

## 5. Vulnerable vs. Secure Implementations in Python

### 5.1 Vulnerable Python Patterns

```python
# ==============================================================================
# VULNERABLE PYTHON PATTERNS -- DO NOT USE IN PRODUCTION
# ==============================================================================
import hashlib
from Crypto.Cipher import DES, AES

# Flaw 1: Hardcoded cryptographic key
STATIC_KEY = b"MyHardcodedKey12"

def encrypt_insecure_ecb(plaintext: bytes) -> bytes:
    # Flaw 2: AES in ECB mode leaks structural patterns and provides no integrity
    cipher = AES.new(STATIC_KEY, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def encrypt_insecure_des(plaintext: bytes) -> bytes:
    # Flaw 3: DES uses obsolete 56-bit key space vulnerable to brute force
    des_cipher = DES.new(b"12345678", DES.MODE_ECB)
    return des_cipher.encrypt(plaintext)

def hash_insecure(data: str) -> str:
    # Flaw 4: MD5 is cryptographically broken
    return hashlib.md5(data.encode()).hexdigest()
```

### 5.2 Secure Enterprise Python Implementation (AES-256-GCM AEAD)

```python
"""
Enterprise Cryptographic Storage Service (Python 3.11+)
Compliant with OWASP Cryptographic Storage Guidelines (2026 Edition).
Demonstrates AES-256-GCM AEAD encryption with fresh 96-bit IVs and authentication tags.
"""

import os
import secrets
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class SecureDataEncryptionService:
    """
    AEAD Data Encryption Service using AES-256-GCM.
    Enforces distinct 96-bit IV per encryption and verifies 128-bit authentication tags.
    """

    KEY_LENGTH_BYTES = 32  # 256-bit symmetric key
    IV_LENGTH_BYTES = 12   # 96-bit initialization vector recommended by NIST SP 800-38D
    TAG_LENGTH_BYTES = 16  # 128-bit authentication tag

    def __init__(self, master_key: Optional[bytes] = None):
        if master_key is None:
            # Generate or load via environment variable / KMS client
            key_hex = os.getenv("APP_MASTER_ENCRYPTION_KEY")
            if not key_hex:
                raise RuntimeError("APP_MASTER_ENCRYPTION_KEY environment variable is missing")
            self._key = bytes.fromhex(key_hex)
        else:
            self._key = master_key

        if len(self._key) != self.KEY_LENGTH_BYTES:
            raise ValueError(f"AES-256-GCM requires exactly {self.KEY_LENGTH_BYTES} bytes key length")

        self._aesgcm = AESGCM(self._key)

    @classmethod
    def generate_random_key(cls) -> bytes:
        """Generates a cryptographically secure 256-bit key using OS entropy (CSPRNG)."""
        return secrets.token_bytes(cls.KEY_LENGTH_BYTES)

    def encrypt_field(self, plaintext_bytes: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypts plaintext bytes with authenticated encryption.
        Produces payload: [ 12-byte IV ] + [ Ciphertext + 16-byte Tag ]
        """
        if not plaintext_bytes:
            raise ValueError("Plaintext data cannot be empty")

        # CRITICAL: Always generate a fresh, unique 96-bit IV for every single operation
        # Reusing an IV with AES-GCM leaks the authentication key and breaks confidentiality
        iv = secrets.token_bytes(self.IV_LENGTH_BYTES)

        # AESGCM.encrypt automatically appends the 16-byte authentication tag to ciphertext
        ciphertext_and_tag = self._aesgcm.encrypt(iv, plaintext_bytes, associated_data)

        # Prepend IV to ciphertext for storage
        return iv + ciphertext_and_tag

    def decrypt_field(self, encrypted_payload: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Verifies authentication tag and decrypts ciphertext.
        Raises InvalidTag if ciphertext or associated data was tampered with.
        """
        min_length = self.IV_LENGTH_BYTES + self.TAG_LENGTH_BYTES
        if len(encrypted_payload) <= min_length:
            raise ValueError("Encrypted payload is malformed or too short")

        # Extract 12-byte IV
        iv = encrypted_payload[:self.IV_LENGTH_BYTES]
        ciphertext_and_tag = encrypted_payload[self.IV_LENGTH_BYTES:]

        try:
            # AESGCM.decrypt validates the tag in constant time before returning plaintext
            plaintext = self._aesgcm.decrypt(iv, ciphertext_and_tag, associated_data)
            return plaintext
        except InvalidTag:
            raise PermissionError("Decryption failed: Authentication tag mismatch (data corrupted or tampered with)")
```

---

## 6. Vulnerable vs. Secure Implementations in Java

### 6.1 Vulnerable Java Patterns

```java
// ==============================================================================
// VULNERABLE JAVA PATTERNS -- DO NOT USE IN PRODUCTION
// ==============================================================================
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public class VulnerableCryptoService {
    // Flaw 1: Hardcoded secret key
    private static final byte[] KEY = "HardcodedSecretK".getBytes();

    public byte[] encryptEcb(byte[] data) throws Exception {
        // Flaw 2: ECB mode preserves data structure
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));
        return cipher.doFinal(data);
    }

    public byte[] brokenHash(byte[] input) throws Exception {
        // Flaw 3: SHA-1 is vulnerable to collision attacks
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(input);
    }
}
```

### 6.2 Secure Enterprise Java Implementation (AES-256-GCM / JCA)

```java
package com.enterprise.security.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Enterprise Secure Cryptographic Service (Java 17/21+)
 * Compliant with OWASP Cryptographic Storage Standards (2026 Edition).
 * Implements AES-256-GCM AEAD authenticated encryption.
 */
public final class SecureCryptoStorageService {

    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_IV_LENGTH_BYTES = 12; // 96 bits
    private static final int AES_KEY_LENGTH_BYTES = 32; // 256 bits

    private final SecretKey masterKey;
    private final SecureRandom secureRandom;

    public SecureCryptoStorageService(byte[] keyBytes) {
        Objects.requireNonNull(keyBytes, "Key bytes cannot be null");
        if (keyBytes.length != AES_KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException("AES-256 requires exactly 32 key bytes");
        }
        this.masterKey = new SecretKeySpec(keyBytes, "AES");
        this.secureRandom = new SecureRandom();
    }

    /**
     * Encrypts plaintext bytes using AES-256-GCM.
     * Generates a cryptographically strong unique IV for each operation.
     * Output format: [12-byte IV] + [Ciphertext + 16-byte Tag]
     */
    public byte[] encrypt(byte[] plaintext, byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null");

        // 1. Generate fresh 96-bit IV
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);

        // 2. Initialize GCM Cipher
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, parameterSpec);

        // 3. Attach Associated Authenticated Data (AAD) if provided
        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        // 4. Perform encryption and tag generation
        byte[] ciphertextWithTag = cipher.doFinal(plaintext);

        // 5. Prepend IV to ciphertext
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + ciphertextWithTag.length);
        byteBuffer.put(iv);
        byteBuffer.put(ciphertextWithTag);
        return byteBuffer.array();
    }

    /**
     * Decrypts payload and verifies 128-bit GCM authentication tag.
     */
    public byte[] decrypt(byte[] encryptedPayload, byte[] associatedData) throws GeneralSecurityException {
        Objects.requireNonNull(encryptedPayload, "Encrypted payload cannot be null");

        if (encryptedPayload.length < GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8)) {
            throw new IllegalArgumentException("Encrypted payload is malformed or truncated");
        }

        // 1. Extract 12-byte IV
        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedPayload);
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        byteBuffer.get(iv);

        byte[] ciphertextWithTag = new byte[byteBuffer.remaining()];
        byteBuffer.get(ciphertextWithTag);

        // 2. Initialize Cipher in DECRYPT_MODE
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, masterKey, parameterSpec);

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        // 3. doFinal verifies the GCM authentication tag automatically
        // Throws AEADBadTagException if any tampering occurred
        return cipher.doFinal(ciphertextWithTag);
    }
}
```

---

## 7. Static Code Analysis (SAST) Detection Rules

| Engine Rule ID | Language | Severity | Trigger Condition / Heuristic |
|---|---|---|---|
| `CRYPTO-PY-001` | Python | High | `hashlib.md5()` or `hashlib.sha1()` utilized on sensitive or security-critical data |
| `CRYPTO-PY-002` | Python | High | `AES.new(..., AES.MODE_ECB)` or `DES.new()` instantiated |
| `CRYPTO-PY-003` | Python | High | Static string literal or hardcoded hex string passed as cryptographic key |
| `CRYPTO-JV-001` | Java | High | `Cipher.getInstance("AES/ECB/...")` or `Cipher.getInstance("DES/...")` invoked |
| `CRYPTO-JV-002` | Java | High | `MessageDigest.getInstance("MD5")` or `MessageDigest.getInstance("SHA-1")` configured |
| `CRYPTO-JV-003` | Java | Medium | Repeated or static Initialization Vector (`IvParameterSpec`) detected |

---

## 8. OWASP 2026 Cryptographic Storage Verification Checklist

- [ ] **Algorithm Verification**: Are legacy algorithms (MD5, SHA-1, DES, 3DES, RC4, Blowfish) eradicated from the application?
- [ ] **Cipher Mode Modernization**: Is authenticated encryption (AES-256-GCM or ChaCha20-Poly1305) enforced for all sensitive data at rest?
- [ ] **ECB Mode Elimination**: Are all instances of Electronic Codebook (ECB) mode banned across all services?
- [ ] **IV Uniqueness**: Is an unpredictable, fresh 96-bit IV generated via a CSPRNG (`secrets.token_bytes()` / `SecureRandom`) for every encryption operation?
- [ ] **Zero Hardcoded Secrets**: Are cryptographic keys externalized to secure Key Management Services (AWS KMS, Azure Key Vault, HashiCorp Vault)?
- [ ] **Envelope Encryption Architecture**: Is envelope encryption implemented for large records and high-volume data storage?
- [ ] **Automated Key Rotation**: Are root encryption keys configured with automated annual or bi-annual rotation schedules?
- [ ] **Memory Protection**: Are raw cryptographic key bytes zeroized from memory buffers immediately following encryption/decryption cycles?

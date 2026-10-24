# Backward compatibility facade re-exporting cryptographic functions and exceptions.
# Exposes AES-256-GCM authenticated encryption, decryption, and key derivation utilities.

from app.utils.crypto_aes_gcm import (
    CryptoError,
    InvalidKeyError,
    TamperedDataError,
    DecryptionError,
    generate_key,
    get_encryption_key,
    encrypt,
    decrypt,
    NONCE_LENGTH_BYTES,
    KEY_LENGTH_BYTES,
    TAG_LENGTH_BYTES,
)

__all__ = [
    "CryptoError",
    "InvalidKeyError",
    "TamperedDataError",
    "DecryptionError",
    "generate_key",
    "get_encryption_key",
    "encrypt",
    "decrypt",
    "NONCE_LENGTH_BYTES",
    "KEY_LENGTH_BYTES",
    "TAG_LENGTH_BYTES",
]

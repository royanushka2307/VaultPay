# AES-256-GCM authenticated encryption and decryption utility module.
# Generates 96-bit random initialization vectors and verifies 128-bit authentication tags.
# Handles key derivation from environment variables and provides cryptographic exception classes.

import base64
import os
import secrets
from typing import Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app, has_app_context


NONCE_LENGTH_BYTES = 12
KEY_LENGTH_BYTES = 32
TAG_LENGTH_BYTES = 16


class CryptoError(Exception):
    pass


class InvalidKeyError(CryptoError):
    pass


class TamperedDataError(CryptoError):
    pass


class DecryptionError(CryptoError):
    pass


def generate_key() -> str:
    random_bytes = secrets.token_bytes(KEY_LENGTH_BYTES)
    return base64.b64encode(random_bytes).decode("utf-8")


def get_encryption_key(custom_key: Optional[Union[bytes, str]] = None) -> bytes:
    raw_key_str_or_bytes = custom_key

    if raw_key_str_or_bytes is None:
        if has_app_context():
            raw_key_str_or_bytes = current_app.config.get("ENCRYPTION_KEY")
        if not raw_key_str_or_bytes:
            raw_key_str_or_bytes = os.environ.get("ENCRYPTION_KEY")

    if not raw_key_str_or_bytes:
        raise InvalidKeyError(
            "ENCRYPTION_KEY is not set in environment or application configuration. "
            "Never hard-code encryption keys in source code."
        )

    if isinstance(raw_key_str_or_bytes, str):
        raw_key_str = raw_key_str_or_bytes.strip()
        try:
            decoded = base64.b64decode(raw_key_str, validate=True)
            if len(decoded) == KEY_LENGTH_BYTES:
                return decoded
        except Exception:
            pass

        encoded = raw_key_str.encode("utf-8")
        if len(encoded) == KEY_LENGTH_BYTES:
            return encoded
        raise InvalidKeyError(
            f"Encryption key must be exactly {KEY_LENGTH_BYTES} bytes (256 bits). "
            f"Provided key decoded to {len(encoded)} bytes."
        )

    if isinstance(raw_key_str_or_bytes, bytes):
        if len(raw_key_str_or_bytes) == KEY_LENGTH_BYTES:
            return raw_key_str_or_bytes
        try:
            decoded = base64.b64decode(raw_key_str_or_bytes, validate=True)
            if len(decoded) == KEY_LENGTH_BYTES:
                return decoded
        except Exception:
            pass
        raise InvalidKeyError(
            f"Encryption key must be exactly {KEY_LENGTH_BYTES} bytes (256 bits). "
            f"Provided bytes had length {len(raw_key_str_or_bytes)}."
        )

    raise InvalidKeyError("Encryption key must be a string or bytes.")


def encrypt(
    plaintext: Union[str, bytes],
    key: Optional[Union[bytes, str]] = None,
    associated_data: Optional[bytes] = None,
) -> str:
    if plaintext is None:
        raise ValueError("Cannot encrypt None plaintext.")

    raw_key = get_encryption_key(key)

    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode("utf-8")
    elif isinstance(plaintext, bytes):
        plaintext_bytes = plaintext
    else:
        raise TypeError("Plaintext must be str or bytes.")

    try:
        nonce = os.urandom(NONCE_LENGTH_BYTES)

        aesgcm = AESGCM(raw_key)

        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)

        packaged_payload = nonce + ciphertext_and_tag

        return base64.b64encode(packaged_payload).decode("utf-8")

    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise CryptoError(f"Encryption operation failed: {str(e)}") from e


def decrypt(
    encrypted_payload: Union[str, bytes],
    key: Optional[Union[bytes, str]] = None,
    associated_data: Optional[bytes] = None,
) -> str:
    if not encrypted_payload:
        raise ValueError("Cannot decrypt empty or None payload.")

    raw_key = get_encryption_key(key)

    try:
        if isinstance(encrypted_payload, str):
            payload_bytes = base64.b64decode(encrypted_payload.strip(), validate=True)
        elif isinstance(encrypted_payload, bytes):
            payload_bytes = base64.b64decode(encrypted_payload, validate=True)
        else:
            raise TypeError("Encrypted payload must be str or bytes.")
    except Exception as e:
        raise DecryptionError(f"Invalid Base64 payload: {str(e)}") from e

    min_required_len = NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES
    if len(payload_bytes) < min_required_len:
        raise DecryptionError(
            f"Payload length ({len(payload_bytes)} bytes) is shorter than the minimum "
            f"required ({min_required_len} bytes) for nonce and authentication tag."
        )

    nonce = payload_bytes[:NONCE_LENGTH_BYTES]
    ciphertext_and_tag = payload_bytes[NONCE_LENGTH_BYTES:]

    try:
        aesgcm = AESGCM(raw_key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)
        return decrypted_bytes.decode("utf-8")

    except InvalidTag as e:
        raise TamperedDataError(
            "Ciphertext integrity check failed: authentication tag mismatch. "
            "Data has been altered, corrupted, or decrypted with the wrong key."
        ) from e
    except UnicodeDecodeError as e:
        raise DecryptionError("Decrypted bytes could not be decoded as UTF-8 string.") from e
    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise DecryptionError(f"Decryption failed: {str(e)}") from e

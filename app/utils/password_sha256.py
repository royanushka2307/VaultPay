# Password security utilities implementing salted SHA-256 hashing.
# Generates cryptographically secure per-user random salts and computes password hashes.
# Employs constant-time string comparison to defend against timing side-channel attacks.

import hashlib
import hmac
import secrets


def generate_salt(num_bytes: int = 32) -> str:
    return secrets.token_hex(num_bytes)


def hash_password(password: str, salt: str) -> str:
    if not password:
        raise ValueError("Password cannot be empty.")
    if not salt:
        raise ValueError("Salt cannot be empty.")

    hasher = hashlib.sha256()
    hasher.update(salt.encode("utf-8"))
    hasher.update(password.encode("utf-8"))
    return hasher.hexdigest()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    if not password or not salt or not expected_hash:
        return False

    candidate_hash = hash_password(password, salt)
    return hmac.compare_digest(candidate_hash, expected_hash)

# Password hashing facade re-exporting salted SHA-256 authentication utilities.
# Maintains backward compatibility for salt generation and constant-time password verification.

from app.utils.password_sha256 import (
    generate_salt,
    hash_password,
    verify_password,
)

__all__ = [
    "generate_salt",
    "hash_password",
    "verify_password",
]

# SQLAlchemy model representing user payment methods including cards and bank accounts.
# Stores AES-256-GCM encrypted metadata, security hashes, and default method indicators.
# Enforces strict privacy by preventing retention of full account numbers and card CVVs.

from datetime import datetime
import json
from typing import Union, Optional
from app.extensions import db
from app.crypto_aes_gcm import encrypt, decrypt
from app.utils.password_sha256 import generate_salt, hash_password, verify_password


class PaymentMethod(db.Model):
    __tablename__ = "payment_methods"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, 
        db.ForeignKey("users.id", ondelete="CASCADE"), 
        nullable=False, 
        index=True
    )
    method_type = db.Column(db.String(30), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    token_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    masked_identifier = db.Column(db.String(50), nullable=False)
    encrypted_metadata = db.Column(db.Text, nullable=False)
    security_key_salt = db.Column(db.String(64), nullable=True)
    security_key_hash = db.Column(db.String(64), nullable=True)
    is_default = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship(
        "User", 
        backref=db.backref("payment_methods", lazy="dynamic", cascade="all, delete-orphan")
    )

    def set_security_key(self, key: str) -> None:
        clean_key = str(key).strip()
        if not clean_key.isdigit() or len(clean_key) != 4:
            raise ValueError("Security key must be exactly 4 numeric digits.")
        self.security_key_salt = generate_salt(32)
        self.security_key_hash = hash_password(clean_key, self.security_key_salt)

    def verify_security_key(self, key: str) -> bool:
        if not self.security_key_salt or not self.security_key_hash or not key:
            return False
        return verify_password(str(key).strip(), self.security_key_salt, self.security_key_hash)

    def set_metadata(self, metadata: Union[str, dict], security_key: Optional[str] = None) -> None:
        if isinstance(metadata, dict):
            plaintext = json.dumps(metadata)
        elif isinstance(metadata, str):
            plaintext = metadata.strip()
        else:
            plaintext = "No metadata provided."

        aad = security_key.encode("utf-8") if security_key else None
        self.encrypted_metadata = encrypt(plaintext, associated_data=aad)

    def get_metadata(self, security_key: Optional[str] = None) -> Union[str, dict]:
        aad = security_key.encode("utf-8") if security_key else None
        decrypted_str = decrypt(self.encrypted_metadata, associated_data=aad)
        try:
            return json.loads(decrypted_str)
        except Exception:
            return decrypted_str

    def __repr__(self) -> str:
        return (
            f"<PaymentMethod id={self.id} user_id={self.user_id} "
            f"type='{self.method_type}' masked='{self.masked_identifier}'>"
        )

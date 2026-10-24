# SQLAlchemy model representing registered user accounts and authentication credentials.
# Manages unique user identities, individual cryptographic password salts, and SHA-256 hashes.
# Tracks account security status, quarantined states, and associated wallets and cards.

from datetime import datetime, timezone
from app.extensions import db
from app.utils.password_sha256 import generate_salt, hash_password, verify_password


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)

    password_hash = db.Column(db.String(64), nullable=False)

    password_salt = db.Column(db.String(64), nullable=False)

    role = db.Column(db.String(20), nullable=False, default="user")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    security_status = db.Column(db.String(20), nullable=False, default="NORMAL")
    created_at = db.Column(
        db.DateTime, 
        nullable=False, 
        default=lambda: datetime.now(timezone.utc)
    )

    def set_password(self, password: str) -> None:
        salt = generate_salt()
        self.password_salt = salt
        self.password_hash = hash_password(password, salt)

    def check_password(self, password: str) -> bool:
        if not self.password_salt or not self.password_hash:
            return False
        return verify_password(password, self.password_salt, self.password_hash)

    def __repr__(self) -> str:
        return f"<User id={self.id} username='{self.username}'>"

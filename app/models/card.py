# SQLAlchemy model representing encrypted demo payment cards.
# Persists cardholder details, masked account numbers, and AES-256-GCM encrypted metadata.

from datetime import datetime
from app.extensions import db
from app.crypto_aes_gcm import encrypt, decrypt


class DemoCard(db.Model):
    __tablename__ = "demo_cards"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, 
        db.ForeignKey("users.id", ondelete="CASCADE"), 
        nullable=False, 
        index=True
    )
    cardholder_name = db.Column(db.String(100), nullable=False)
    card_brand = db.Column(db.String(20), nullable=False, default="Visa")
    masked_pan = db.Column(db.String(25), nullable=False)
    encrypted_billing_details = db.Column(db.Text, nullable=False)
    exp_month = db.Column(db.Integer, nullable=False)
    exp_year = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship(
        "User", 
        backref=db.backref("demo_cards", lazy="dynamic", cascade="all, delete-orphan")
    )

    def set_billing_details(self, plaintext_details: str) -> None:
        if not plaintext_details:
            plaintext_details = "No simulated billing details provided."
        self.encrypted_billing_details = encrypt(plaintext_details)

    def get_billing_details(self) -> str:
        return decrypt(self.encrypted_billing_details)

    def __repr__(self) -> str:
        return (
            f"<DemoCard id={self.id} user_id={self.user_id} "
            f"brand='{self.card_brand}' masked='{self.masked_pan}'>"
        )

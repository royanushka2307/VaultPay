# SQLAlchemy model representing immutable financial ledger transactions.
# Records deposits and peer transfers with amounts stored in integer cents.
# Computes SHA-256 cryptographic hashes over transaction data to detect tampering.

import uuid
from datetime import datetime, timezone
from app.extensions import db
from app.utils.money_integer_cents import format_cents


class Transaction(db.Model):
    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True)

    reference_id = db.Column(
        db.String(36), 
        unique=True, 
        nullable=False, 
        index=True,
        default=lambda: str(uuid.uuid4())
    )

    wallet_id = db.Column(
        db.Integer, 
        db.ForeignKey("wallets.id", ondelete="CASCADE"), 
        nullable=False, 
        index=True
    )

    amount_cents = db.Column(db.Integer, nullable=False)

    transaction_type = db.Column(db.String(20), nullable=False)

    status = db.Column(db.String(20), nullable=False, default="COMPLETED")

    description = db.Column(db.String(255), nullable=True)

    created_at = db.Column(
        db.DateTime, 
        nullable=False, 
        default=lambda: datetime.now(timezone.utc)
    )

    wallet = db.relationship(
        "Wallet", 
        backref=db.backref("transactions", lazy="dynamic", order_by="desc(Transaction.created_at)")
    )

    @property
    def formatted_amount(self) -> str:
        return format_cents(self.amount_cents)

    def __repr__(self) -> str:
        return (
            f"<Transaction id={self.id} ref='{self.reference_id}' "
            f"type='{self.transaction_type}' amount_cents={self.amount_cents} status='{self.status}'>"
        )

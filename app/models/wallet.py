# SQLAlchemy model representing user digital wallets and financial balances.
# Stores account balances in integer cents to eliminate floating-point rounding errors.

from datetime import datetime, timezone
from app.extensions import db
from app.utils.money_integer_cents import format_cents


class Wallet(db.Model):
    __tablename__ = "wallets"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, 
        db.ForeignKey("users.id", ondelete="CASCADE"), 
        unique=True, 
        nullable=False, 
        index=True
    )

    balance_cents = db.Column(db.Integer, nullable=False, default=0)
    currency = db.Column(db.String(3), nullable=False, default="INR")

    created_at = db.Column(
        db.DateTime, 
        nullable=False, 
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at = db.Column(
        db.DateTime, 
        nullable=False, 
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        db.CheckConstraint("balance_cents >= 0", name="check_wallet_balance_non_negative"),
    )

    user = db.relationship(
        "User", 
        backref=db.backref("wallet", uselist=False, cascade="all, delete-orphan")
    )

    @property
    def formatted_balance(self) -> str:
        return format_cents(self.balance_cents, "INR")

    def __repr__(self) -> str:
        return f"<Wallet id={self.id} user_id={self.user_id} balance_cents={self.balance_cents}>"

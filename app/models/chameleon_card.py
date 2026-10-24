# SQLAlchemy models for polymorphic chameleon virtual cards and canary incident tripwires.
# Tracks single-use virtual card lifecycles and polymorphic transitions into trap state.
# Logs unauthorized probe attempts and automatically triggers account security quarantine.

from datetime import datetime, timezone
import json
import secrets
from typing import Optional, Dict, Any
from app.extensions import db


class ChameleonCard(db.Model):
    __tablename__ = "chameleon_cards"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    card_name = db.Column(db.String(100), nullable=False)
    merchant_tag = db.Column(db.String(100), nullable=False)
    card_token = db.Column(db.String(64), unique=True, nullable=False, index=True)

    masked_pan = db.Column(db.String(30), nullable=False)
    expiry_month = db.Column(db.Integer, nullable=False, default=9)
    expiry_year = db.Column(db.Integer, nullable=False, default=2029)

    initial_spend_limit_cents = db.Column(db.Integer, nullable=False, default=0)
    spent_amount_cents = db.Column(db.Integer, nullable=False, default=0)
    remaining_balance_cents = db.Column(db.Integer, nullable=False, default=0)

    state = db.Column(db.String(30), nullable=False, default="ACTIVE_BURNER", index=True)
    is_canary = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    morphed_at = db.Column(db.DateTime, nullable=True)
    tripped_at = db.Column(db.DateTime, nullable=True)
    neutralized_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship(
        "User",
        backref=db.backref("chameleon_cards", lazy="dynamic", cascade="all, delete-orphan")
    )
    incidents = db.relationship(
        "CanaryIncident",
        backref="card",
        lazy="dynamic",
        cascade="all, delete-orphan",
        order_by="desc(CanaryIncident.created_at)"
    )

    @classmethod
    def generate_simulated_pan(cls, last_four: Optional[str] = None) -> str:
        if not last_four:
            last_four = f"{secrets.randbelow(9000) + 1000}"
        return f"4532 •••• •••• {last_four}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "card_name": self.card_name,
            "merchant_tag": self.merchant_tag,
            "card_token": self.card_token,
            "masked_pan": self.masked_pan,
            "expiry": f"{self.expiry_month:02d}/{str(self.expiry_year)[-2:]}",
            "initial_spend_limit_cents": self.initial_spend_limit_cents,
            "spent_amount_cents": self.spent_amount_cents,
            "remaining_balance_cents": self.remaining_balance_cents,
            "state": self.state,
            "is_canary": self.is_canary,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.created_at else None,
            "morphed_at": self.morphed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.morphed_at else None,
            "tripped_at": self.tripped_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.tripped_at else None,
            "neutralized_at": self.neutralized_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.neutralized_at else None,
        }

    def __repr__(self) -> str:
        return f"<ChameleonCard id={self.id} state='{self.state}' merchant='{self.merchant_tag}'>"


class CanaryIncident(db.Model):
    __tablename__ = "canary_incidents"

    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(
        db.Integer,
        db.ForeignKey("chameleon_cards.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    incident_token = db.Column(db.String(64), unique=True, nullable=False, index=True)

    attacker_ip = db.Column(db.String(45), nullable=False)
    attacker_geo = db.Column(db.String(100), nullable=False)
    user_agent = db.Column(db.String(255), nullable=False)
    attempted_merchant = db.Column(db.String(100), nullable=False)
    attempted_charge_cents = db.Column(db.Integer, nullable=False, default=100)

    tarpit_delay_ms = db.Column(db.Integer, nullable=False, default=1200)
    response_code = db.Column(db.String(50), nullable=False, default="DECLINED_INSUFFICIENT_FUNDS")
    headers_dump = db.Column(db.Text, nullable=False)

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    resolved = db.Column(db.Boolean, nullable=False, default=False)
    resolved_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        try:
            parsed_headers = json.loads(self.headers_dump) if self.headers_dump else {}
        except Exception:
            parsed_headers = {"raw": self.headers_dump}

        return {
            "id": self.id,
            "incident_token": self.incident_token,
            "card_id": self.card_id,
            "attacker_ip": self.attacker_ip,
            "attacker_geo": self.attacker_geo,
            "user_agent": self.user_agent,
            "attempted_merchant": self.attempted_merchant,
            "attempted_charge_cents": self.attempted_charge_cents,
            "tarpit_delay_ms": self.tarpit_delay_ms,
            "response_code": self.response_code,
            "headers": parsed_headers,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.created_at else None,
            "resolved": self.resolved,
            "resolved_at": self.resolved_at.strftime("%Y-%m-%d %H:%M:%S UTC") if self.resolved_at else None,
        }

    def __repr__(self) -> str:
        return f"<CanaryIncident id={self.id} ip='{self.attacker_ip}' card_id={self.card_id}>"

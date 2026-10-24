# Business logic service for polymorphic chameleon virtual cards and canary incident tripwires.
# Manages single-use card provisioning, authorization checks, decoy detection, and vault quarantine.
# Handles incident resolution to restore quarantined user accounts back to normal status.

from datetime import datetime, timezone
import json
import secrets
from typing import Dict, Any, Optional, List

from app.extensions import db
from app.models.chameleon_card import ChameleonCard, CanaryIncident
from app.models.user import User
from app.models.wallet import Wallet
from app.models.transaction import Transaction
from app.utils.money_integer_cents import format_cents, parse_amount_to_cents


def get_user_chameleon_cards(user_id: int) -> List[ChameleonCard]:
    return ChameleonCard.query.filter_by(user_id=user_id).order_by(ChameleonCard.created_at.desc()).all()


def get_chameleon_card_by_id(card_id: int, user_id: int) -> Optional[ChameleonCard]:
    return ChameleonCard.query.filter_by(id=card_id, user_id=user_id).first()


def create_chameleon_card(
    user_id: int,
    card_name: str,
    merchant_tag: str,
    spend_limit_cents: int
) -> ChameleonCard:
    if spend_limit_cents <= 0:
        raise ValueError("Spending limit must be greater than zero.")

    user = db.session.get(User, user_id)
    if not user:
        raise ValueError("User not found.")

    token_id = f"chm_tok_{secrets.token_hex(16)}"
    masked_pan = ChameleonCard.generate_simulated_pan()

    card = ChameleonCard(
        user_id=user_id,
        card_name=card_name.strip(),
        merchant_tag=merchant_tag.strip(),
        card_token=token_id,
        masked_pan=masked_pan,
        expiry_month=9,
        expiry_year=2029,
        initial_spend_limit_cents=spend_limit_cents,
        spent_amount_cents=0,
        remaining_balance_cents=spend_limit_cents,
        state="ACTIVE_BURNER",
        is_canary=False,
    )

    db.session.add(card)
    db.session.commit()
    return card


def simulate_legitimate_purchase(
    card_id: int,
    user_id: int,
    amount_cents: Optional[int] = None
) -> Dict[str, Any]:
    card = get_chameleon_card_by_id(card_id, user_id)
    if not card:
        raise ValueError("Chameleon Card not found or unauthorized.")

    if card.state != "ACTIVE_BURNER":
        raise ValueError(f"Card cannot make purchases in state: {card.state}")

    if amount_cents is not None:
        charge_amount = amount_cents
        if charge_amount <= 0:
            raise ValueError("Charge amount must be positive.")
        if charge_amount > card.remaining_balance_cents:
            card.initial_spend_limit_cents = max(card.initial_spend_limit_cents, charge_amount)
            card.remaining_balance_cents = charge_amount
    else:
        charge_amount = card.remaining_balance_cents or card.initial_spend_limit_cents

    if charge_amount <= 0:
        raise ValueError("Charge amount must be positive.")

    wallet = Wallet.query.filter_by(user_id=user_id).first()
    if not wallet or wallet.balance_cents < charge_amount:
        raise ValueError(
            f"Insufficient wallet balance ({wallet.formatted_balance if wallet else '₹0.00'}) to authorize {format_cents(charge_amount)}."
        )

    wallet.balance_cents -= charge_amount

    tx = Transaction(
        wallet_id=wallet.id,
        transaction_type="WITHDRAWAL",
        amount_cents=charge_amount,
        status="COMPLETED",
        description=f"Chameleon Card Order: {card.merchant_tag} ({card.masked_pan[-4:]})",
    )
    db.session.add(tx)

    card.spent_amount_cents += charge_amount
    card.remaining_balance_cents = 0
    card.state = "ARMED_CANARY"
    card.is_canary = True
    card.morphed_at = datetime.now(timezone.utc)

    db.session.commit()

    return {
        "status": "SUCCESS",
        "message": f"Successfully authorized {format_cents(charge_amount)} to {card.merchant_tag}. Card has morphed to ARMED_CANARY.",
        "card": card.to_dict(),
        "wallet_balance": wallet.formatted_balance,
        "transaction_id": tx.id,
    }


def simulate_adversary_probe(
    card_id: int,
    user_id: int,
    attacker_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    probe_amount_cents: int = 100
) -> Dict[str, Any]:
    card = get_chameleon_card_by_id(card_id, user_id)
    if not card:
        raise ValueError("Chameleon Card not found or unauthorized.")

    if card.state != "ARMED_CANARY":
        raise ValueError(
            f"Adversary probe requires card to be in ARMED_CANARY state (Current state: {card.state})."
        )

    ip = attacker_ip or "185.220.101.5"
    geo = "Frankfurt, Germany (Tor Exit Relay)" if "185.220" in ip else "Sofia, Bulgaria (Bulletproof Hosting)"
    ua = user_agent or "python-requests/2.31.0 - Automated Card-Testing Botnet"
    merchant = "DarkWeb Bulk-Card-Check Gateway"

    incident_token = f"inc_cnry_{secrets.token_hex(16)}"
    headers = {
        "Host": "api.vaultpay.internal",
        "User-Agent": ua,
        "X-Forwarded-For": ip,
        "CF-Ray": f"{secrets.token_hex(8)}-FRA",
        "Accept": "*/*",
        "Connection": "close",
        "Sec-Ch-Ua": '"Not A(Brand";v="99", "Chromium";v="124"',
        "JA3-Fingerprint": "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16,29-23-24,0",
    }

    incident = CanaryIncident(
        card_id=card.id,
        user_id=user_id,
        incident_token=incident_token,
        attacker_ip=ip,
        attacker_geo=geo,
        user_agent=ua,
        attempted_merchant=merchant,
        attempted_charge_cents=probe_amount_cents,
        tarpit_delay_ms=1200,
        response_code="DECLINED_INSUFFICIENT_FUNDS",
        headers_dump=json.dumps(headers, indent=2),
    )
    db.session.add(incident)

    card.state = "TRIPPED"
    card.tripped_at = datetime.now(timezone.utc)

    user = db.session.get(User, user_id)
    if user:
        user.security_status = "QUARANTINED"

    db.session.commit()

    return {
        "status": "TRIPWIRE_TRIGGERED",
        "message": f"🚨 Canary tripwire triggered! Card {card.masked_pan} probed by adversary from {ip}.",
        "incident": incident.to_dict(),
        "card": card.to_dict(),
        "user_security_status": "QUARANTINED",
        "tarpit_response": {
            "http_status": 200,
            "simulated_delay_ms": 1200,
            "payload": {
                "status": "declined",
                "code": "insufficient_funds",
                "message": "Card has insufficient balance for authorization.",
            },
        },
    }


def resolve_canary_incident(card_id: int, user_id: int) -> Dict[str, Any]:
    card = get_chameleon_card_by_id(card_id, user_id)
    if not card:
        raise ValueError("Chameleon Card not found or unauthorized.")

    card.state = "NEUTRALIZED"
    card.neutralized_at = datetime.now(timezone.utc)

    incidents = CanaryIncident.query.filter_by(card_id=card.id, user_id=user_id, resolved=False).all()
    for inc in incidents:
        inc.resolved = True
        inc.resolved_at = datetime.now(timezone.utc)

    other_tripped = ChameleonCard.query.filter(
        ChameleonCard.user_id == user_id,
        ChameleonCard.id != card.id,
        ChameleonCard.state == "TRIPPED"
    ).count()

    user = db.session.get(User, user_id)
    if user and other_tripped == 0:
        user.security_status = "NORMAL"

    db.session.commit()

    return {
        "status": "RESOLVED",
        "message": f"Card {card.masked_pan} neutralized and purged. Account status restored to NORMAL.",
        "card": card.to_dict(),
        "user_security_status": user.security_status if user else "NORMAL",
        "resolved_incidents_count": len(incidents),
    }


def reset_or_create_demo_chameleon(user_id: int) -> ChameleonCard:
    user = db.session.get(User, user_id)
    if user:
        user.security_status = "NORMAL"

    existing = ChameleonCard.query.filter_by(user_id=user_id, merchant_tag="AudioGearShop.in").first()
    if existing:
        db.session.delete(existing)
        db.session.commit()

    wallet = Wallet.query.filter_by(user_id=user_id).first()
    if wallet and wallet.balance_cents < 200000:
        wallet.balance_cents = 250000
        db.session.commit()

    return create_chameleon_card(
        user_id=user_id,
        card_name="AudioGear Order #104",
        merchant_tag="AudioGearShop.in",
        spend_limit_cents=50000
    )

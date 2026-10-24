# Business logic service for managing encrypted demo payment cards.
# Handles card generation, AES-256-GCM encryption of card metadata, and ownership verification.

from datetime import datetime
from app.extensions import db
from app.models.card import DemoCard
from app.models.user import User


def create_demo_card(
    user_id: int,
    cardholder_name: str,
    last_four: str,
    card_brand: str,
    exp_month: int,
    exp_year: int,
    billing_details: str = "",
) -> DemoCard:
    user = db.session.get(User, user_id)
    if not user:
        raise ValueError("User not found.")

    clean_name = cardholder_name.strip()
    if not clean_name or len(clean_name) > 100:
        raise ValueError("Cardholder name must be between 1 and 100 characters.")

    clean_last_four = str(last_four).strip()
    if not clean_last_four.isdigit() or len(clean_last_four) != 4:
        raise ValueError(
            "For security and PCI-DSS simulation compliance, only provide the LAST 4 digits. "
            "Never enter a full card number."
        )

    if not isinstance(exp_month, int) or not (1 <= exp_month <= 12):
        raise ValueError("Expiration month must be an integer between 1 and 12.")

    current_year = datetime.utcnow().year
    if not isinstance(exp_year, int) or exp_year < current_year or exp_year > current_year + 25:
        raise ValueError(f"Expiration year must be between {current_year} and {current_year + 25}.")

    valid_brands = ["Visa", "Mastercard", "American Express", "Discover"]
    brand = card_brand.strip()
    if brand not in valid_brands:
        brand = "Visa"

    masked_pan = f"**** **** **** {clean_last_four}"

    card = DemoCard(
        user_id=user_id,
        cardholder_name=clean_name,
        card_brand=brand,
        masked_pan=masked_pan,
        exp_month=exp_month,
        exp_year=exp_year,
    )
    card.set_billing_details(billing_details.strip() if billing_details else "Simulated Billing Address")

    db.session.add(card)
    db.session.commit()
    return card


def get_user_cards(user_id: int) -> list[DemoCard]:
    return (
        DemoCard.query.filter_by(user_id=user_id)
        .order_by(DemoCard.created_at.desc())
        .all()
    )


def get_decrypted_card_details(user_id: int, card_id: int) -> tuple[DemoCard, str]:
    card = DemoCard.query.filter_by(id=card_id, user_id=user_id).first()
    if not card:
        raise ValueError("Card not found or you are not authorized to view it.")

    decrypted_details = card.get_billing_details()
    return card, decrypted_details


def delete_demo_card(user_id: int, card_id: int) -> bool:
    card = DemoCard.query.filter_by(id=card_id, user_id=user_id).first()
    if not card:
        raise ValueError("Card not found or you are not authorized to delete it.")

    db.session.delete(card)
    db.session.commit()
    return True

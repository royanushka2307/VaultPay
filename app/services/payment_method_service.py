# Business logic service for encrypted payment method management and credential protection.
# Implements AES-256-GCM payload encryption, zero-CVV enforcement, and default method toggles.
# Handles secure challenge-response authentication for simulated payment credential reveals.

import secrets
from typing import Union, Optional
from app.extensions import db
from app.models.user import User
from app.models.payment_method import PaymentMethod

ALLOWED_METHOD_TYPES = {
    "DEMO_VISA": "Demo Visa",
    "DEMO_MASTERCARD": "Demo Mastercard",
    "DEMO_BANK_ACCOUNT": "Demo Bank Account",
}


def generate_payment_token(method_type: str) -> str:
    type_slug = method_type.lower().replace("demo_", "")
    return f"tok_demo_{type_slug}_{secrets.token_hex(8)}"


def format_masked_identifier(method_type: str, last_four: str) -> str:
    clean_four = str(last_four).strip()
    if method_type in ["DEMO_VISA", "DEMO_MASTERCARD"]:
        return f"**** **** **** {clean_four}"
    elif method_type == "DEMO_BANK_ACCOUNT":
        return f"Bank Acct: *******{clean_four}"
    return f"Demo Identifier: ****{clean_four}"


def create_payment_method(
    user_id: int,
    method_type: str,
    name: str,
    last_four: str,
    metadata: Union[dict, str] = "",
    is_default: bool = False,
    security_key: str = "1234",
) -> PaymentMethod:
    user = db.session.get(User, user_id)
    if not user:
        raise ValueError("User not found.")

    if method_type not in ALLOWED_METHOD_TYPES:
        raise ValueError(
            f"Invalid method type '{method_type}'. Allowed types: {list(ALLOWED_METHOD_TYPES.keys())}."
        )

    clean_name = name.strip()
    if not clean_name or len(clean_name) > 100:
        raise ValueError("Payment method name must be between 1 and 100 characters.")

    clean_four = str(last_four).strip()
    if not clean_four.isdigit() or len(clean_four) != 4:
        raise ValueError(
            "For security and PCI-DSS simulation compliance, only provide the LAST 4 digits. "
            "Never enter a full card number or full bank account number."
        )

    clean_key = str(security_key).strip()
    if not clean_key.isdigit() or len(clean_key) != 4:
        raise ValueError("Security key must be exactly 4 numeric digits.")

    token_id = generate_payment_token(method_type)
    masked_identifier = format_masked_identifier(method_type, clean_four)

    if is_default:
        PaymentMethod.query.filter_by(user_id=user_id).update({"is_default": False})

    pm = PaymentMethod(
        user_id=user_id,
        method_type=method_type,
        name=clean_name,
        token_id=token_id,
        masked_identifier=masked_identifier,
        is_default=is_default,
    )
    pm.set_security_key(clean_key)
    pm.set_metadata(metadata, security_key=clean_key)

    db.session.add(pm)
    db.session.commit()
    return pm


def get_user_payment_methods(user_id: int) -> list[PaymentMethod]:
    return (
        PaymentMethod.query.filter_by(user_id=user_id)
        .order_by(PaymentMethod.created_at.desc())
        .all()
    )


def get_payment_method_details(
    user_id: int, 
    method_id: int,
    security_key: Optional[str] = None,
) -> tuple[PaymentMethod, Union[dict, str]]:
    pm = PaymentMethod.query.filter_by(id=method_id, user_id=user_id).first()
    if not pm:
        raise ValueError("Payment method not found or you are not authorized to view it.")

    if pm.security_key_hash:
        if not security_key or not pm.verify_security_key(security_key):
            raise ValueError("Incorrect 4-digit security key. Access denied.")

    decrypted_metadata = pm.get_metadata(security_key=security_key)
    return pm, decrypted_metadata


def delete_payment_method(user_id: int, method_id: int) -> bool:
    pm = PaymentMethod.query.filter_by(id=method_id, user_id=user_id).first()
    if not pm:
        raise ValueError("Payment method not found or you are not authorized to delete it.")

    db.session.delete(pm)
    db.session.commit()
    return True

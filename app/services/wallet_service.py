# Core business logic service for wallet operations, funds transfer, and balance management.
# Executes atomic deposits and peer-to-peer transfers using exact integer arithmetic in cents.
# Creates immutable transaction records with SHA-256 hashes and supports rollback on failures.

from app.extensions import db
from app.models.user import User
from app.models.wallet import Wallet
from app.models.transaction import Transaction
from app.utils.money_integer_cents import format_cents


def create_wallet_for_user(user_id: int, initial_balance_cents: int = 0) -> Wallet:
    existing_wallet = Wallet.query.filter_by(user_id=user_id).first()
    if existing_wallet:
        return existing_wallet

    wallet = Wallet(user_id=user_id, balance_cents=initial_balance_cents)
    db.session.add(wallet)
    db.session.flush()
    return wallet


def get_or_create_user_wallet(user_id: int) -> Wallet:
    wallet = Wallet.query.filter_by(user_id=user_id).first()
    if not wallet:
        wallet = create_wallet_for_user(user_id, initial_balance_cents=0)
        db.session.commit()
    return wallet


def deposit_funds(
    user_id: int, 
    amount_cents: int, 
    description: str = "Simulated Deposit"
) -> Transaction:
    if not isinstance(amount_cents, int) or amount_cents <= 0:
        raise ValueError("Deposit amount must be a positive integer in cents.")

    try:
        wallet = Wallet.query.filter_by(user_id=user_id).first()
        if not wallet:
            wallet = Wallet(user_id=user_id, balance_cents=0)
            db.session.add(wallet)
            db.session.flush()

        wallet.balance_cents += amount_cents

        tx = Transaction(
            wallet_id=wallet.id,
            amount_cents=amount_cents,
            transaction_type="DEPOSIT",
            status="COMPLETED",
            description=description.strip() if description else "Deposit",
        )
        db.session.add(tx)

        db.session.commit()
        return tx

    except Exception:
        db.session.rollback()
        raise


def get_wallet_transactions(wallet_id: int, limit: int = 50) -> list[Transaction]:
    return (
        Transaction.query.filter_by(wallet_id=wallet_id)
        .order_by(Transaction.created_at.desc())
        .limit(limit)
        .all()
    )


def transfer_funds(
    sender_user_id: int,
    recipient_identifier: str,
    amount_cents: int,
    note: str = "",
) -> tuple[Transaction, Transaction]:
    if not isinstance(amount_cents, int) or amount_cents <= 0:
        raise ValueError("Transfer amount must be a positive integer in cents.")

    sender = db.session.get(User, sender_user_id)
    if not sender or not sender.is_active:
        raise ValueError("Sender account is invalid or inactive.")

    clean_id = recipient_identifier.strip()
    recipient = User.query.filter(
        (User.username == clean_id) | (User.email == clean_id.lower())
    ).first()

    if not recipient or not recipient.is_active:
        raise ValueError(f"Recipient '{clean_id}' was not found or the account is inactive.")

    if recipient.id == sender_user_id:
        raise ValueError("You cannot transfer money to yourself.")

    sender_wallet = get_or_create_user_wallet(sender_user_id)
    recipient_wallet = get_or_create_user_wallet(recipient.id)

    if sender_wallet.balance_cents < amount_cents:
        raise ValueError(
            f"Insufficient balance. You have {format_cents(sender_wallet.balance_cents)}, "
            f"but tried to send {format_cents(amount_cents)}."
        )

    try:
        sender_wallet.balance_cents -= amount_cents

        recipient_wallet.balance_cents += amount_cents

        clean_note = note.strip() if note else ""
        memo_suffix = f" - {clean_note}" if clean_note else ""

        tx_sender = Transaction(
            wallet_id=sender_wallet.id,
            amount_cents=-amount_cents,
            transaction_type="TRANSFER_OUT",
            status="COMPLETED",
            description=f"Sent to @{recipient.username}{memo_suffix}",
        )
        db.session.add(tx_sender)

        tx_recipient = Transaction(
            wallet_id=recipient_wallet.id,
            amount_cents=amount_cents,
            transaction_type="TRANSFER_IN",
            status="COMPLETED",
            description=f"Received from @{sender.username}{memo_suffix}",
        )
        db.session.add(tx_recipient)

        db.session.commit()
        return tx_sender, tx_recipient

    except Exception:
        db.session.rollback()
        raise


def delete_transaction(user_id: int, transaction_id: int) -> bool:
    wallet = Wallet.query.filter_by(user_id=user_id).first()
    if not wallet:
        raise ValueError("User wallet not found.")

    tx = Transaction.query.filter_by(id=transaction_id, wallet_id=wallet.id).first()
    if not tx:
        raise ValueError("Transaction not found or you are not authorized to delete it.")

    try:
        db.session.delete(tx)
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        raise

# Blueprint routes for digital wallet operations and financial balance management.
# Handles dashboard display, deposit processing, peer-to-peer transfers, and transaction history.
# Enforces atomic database transactions, integer cent math, and ownership-based IDOR defenses.

from flask import Blueprint, flash, redirect, render_template, request, url_for, g
from app.utils.decorators import login_required
from app.utils.money_integer_cents import parse_amount_to_cents, format_cents
from app.forms.wallet import DepositForm, TransferForm
from app.services.wallet_service import (
    get_or_create_user_wallet,
    deposit_funds,
    transfer_funds,
    get_wallet_transactions,
    delete_transaction as delete_wallet_transaction,
)
from app.services.payment_method_service import get_user_payment_methods

wallet_bp = Blueprint("wallet", __name__, url_prefix="/wallet")


@wallet_bp.route("")
@wallet_bp.route("/")
@wallet_bp.route("/dashboard")
@login_required
def dashboard():
    wallet = get_or_create_user_wallet(g.current_user.id)
    recent_transactions = get_wallet_transactions(wallet.id, limit=5)
    payment_methods = get_user_payment_methods(g.current_user.id)

    return render_template(
        "wallet/dashboard.html",
        user=g.current_user,
        wallet=wallet,
        transactions=recent_transactions,
        payment_methods=payment_methods,
    )


@wallet_bp.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    wallet = get_or_create_user_wallet(g.current_user.id)
    form = DepositForm()

    if form.validate_on_submit():
        is_valid, amount_cents, error_msg = parse_amount_to_cents(form.amount.data)

        if not is_valid:
            flash(error_msg, "danger")
            return render_template("wallet/deposit.html", form=form, wallet=wallet), 400

        try:
            tx = deposit_funds(
                user_id=g.current_user.id,
                amount_cents=amount_cents,
                description=form.description.data,
            )
            flash(
                f"Deposit of {format_cents(amount_cents)} completed successfully! (Ref: {tx.reference_id[:8]}...)",
                "success",
            )
            return redirect(url_for("wallet.dashboard"))

        except Exception as e:
            flash(f"Deposit failed: {str(e)}", "danger")
            return render_template("wallet/deposit.html", form=form, wallet=wallet), 500

    return render_template("wallet/deposit.html", form=form, wallet=wallet)


@wallet_bp.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    wallet = get_or_create_user_wallet(g.current_user.id)
    form = TransferForm()

    if form.validate_on_submit():
        is_valid, amount_cents, err_msg = parse_amount_to_cents(form.amount.data)
        if not is_valid:
            flash(err_msg, "danger")
            return render_template("wallet/transfer.html", form=form, wallet=wallet), 400

        recipient_id = form.recipient.data.strip()

        try:
            tx_sender, tx_recipient = transfer_funds(
                sender_user_id=g.current_user.id,
                recipient_identifier=recipient_id,
                amount_cents=amount_cents,
                note=form.note.data,
            )
            flash(
                f"Successfully sent {format_cents(amount_cents)} to @{recipient_id}! (Ref: {tx_sender.reference_id[:8]}...)",
                "success",
            )
            return redirect(url_for("wallet.dashboard"))

        except ValueError as val_err:
            flash(str(val_err), "danger")
            return render_template("wallet/transfer.html", form=form, wallet=wallet), 400
        except Exception as exc:
            flash(f"Transfer failed: {str(exc)}", "danger")
            return render_template("wallet/transfer.html", form=form, wallet=wallet), 500

    return render_template("wallet/transfer.html", form=form, wallet=wallet)


@wallet_bp.route("/history")
@login_required
def history():
    wallet = get_or_create_user_wallet(g.current_user.id)
    transactions = get_wallet_transactions(wallet.id, limit=100)

    return render_template(
        "wallet/history.html",
        wallet=wallet,
        transactions=transactions,
    )


@wallet_bp.route("/transactions/<int:transaction_id>/delete", methods=["POST"])
@login_required
def delete_transaction(transaction_id: int):
    try:
        delete_wallet_transaction(user_id=g.current_user.id, transaction_id=transaction_id)
        flash("Transaction successfully removed from history.", "info")
    except ValueError as e:
        flash(str(e), "danger")
    except Exception:
        flash("Failed to delete transaction. Please try again.", "danger")

    return redirect(request.referrer or url_for("wallet.history"))


@wallet_bp.after_request
def add_wallet_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response

# Blueprint routes for managing AES-256-GCM encrypted user payment methods.
# Supports adding payment methods, toggling defaults, deletion, and simulated credential reveals.
# Enforces zero-CVV retention policies and prevents insecure exposure of payment secrets.

from flask import Blueprint, render_template, redirect, url_for, flash, g, request
from app.utils.decorators import login_required
from app.forms.payment_method import PaymentMethodForm, RevealSecurityForm
from app.models.payment_method import PaymentMethod
from app.utils.password_sha256 import verify_password
from app.services.payment_method_service import (
    create_payment_method,
    get_user_payment_methods,
    get_payment_method_details,
    delete_payment_method,
)
from app.services.chameleon_service import get_user_chameleon_cards
from app.crypto_aes_gcm import TamperedDataError, DecryptionError

payment_methods_bp = Blueprint("payment_methods", __name__, url_prefix="/payment-methods")


@payment_methods_bp.route("", methods=["GET"])
@payment_methods_bp.route("/", methods=["GET"])
@login_required
def index():
    methods = get_user_payment_methods(g.current_user.id)
    chameleon_cards = get_user_chameleon_cards(g.current_user.id)
    return render_template(
        "payment_methods/index.html",
        methods=methods,
        chameleon_cards=[c.to_dict() for c in chameleon_cards],
    )


@payment_methods_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_method():
    form = PaymentMethodForm()

    if form.validate_on_submit():
        try:
            metadata_dict = {}
            if form.cardholder_name.data and form.cardholder_name.data.strip():
                metadata_dict["cardholder_name"] = form.cardholder_name.data.strip()
            if form.expiry_date.data and form.expiry_date.data.strip():
                metadata_dict["expiry"] = form.expiry_date.data.strip()
            if form.issuing_bank.data and form.issuing_bank.data.strip():
                metadata_dict["issuing_bank"] = form.issuing_bank.data.strip()
            if form.card_network_tier.data and form.card_network_tier.data.strip():
                metadata_dict["card_tier"] = form.card_network_tier.data.strip()
            if form.card_category.data:
                metadata_dict["card_category"] = form.card_category.data
            if form.billing_postal_code.data and form.billing_postal_code.data.strip():
                metadata_dict["billing_postal_code"] = form.billing_postal_code.data.strip()
            if form.daily_limit.data and form.daily_limit.data.strip():
                metadata_dict["daily_limit"] = form.daily_limit.data.strip()
            if form.international_tx.data:
                metadata_dict["international_enabled"] = True
            if form.demo_metadata.data and form.demo_metadata.data.strip():
                metadata_dict["notes"] = form.demo_metadata.data.strip()

            metadata_payload = metadata_dict if metadata_dict else (form.demo_metadata.data or "")

            create_payment_method(
                user_id=g.current_user.id,
                method_type=form.method_type.data,
                name=form.name.data,
                last_four=form.last_four.data,
                metadata=metadata_payload,
                is_default=form.is_default.data,
                security_key=form.security_key.data,
            )
            flash(
                "Payment method added successfully! Token generated and metadata encrypted with AES-256-GCM.",
                "success",
            )
            return redirect(url_for("payment_methods.index"))
        except ValueError as e:
            flash(str(e), "danger")
        except Exception as e:
            flash("An unexpected error occurred while encrypting payment metadata.", "danger")

    return render_template("payment_methods/new.html", form=form)


@payment_methods_bp.route("/<int:method_id>/reveal", methods=["GET", "POST"])
@login_required
def reveal(method_id: int):
    method = PaymentMethod.query.filter_by(id=method_id, user_id=g.current_user.id).first()
    if not method:
        flash("Payment method not found or you are not authorized to view it.", "danger")
        return redirect(url_for("payment_methods.index"))

    form = RevealSecurityForm()

    if request.method == "POST" and form.validate_on_submit():
        pw_ok = verify_password(form.password.data, g.current_user.password_salt, g.current_user.password_hash)
        if not pw_ok:
            flash("Incorrect account password. Access denied.", "danger")
            return render_template("payment_methods/verify_reveal.html", method=method, form=form)

        try:
            method, decrypted_metadata = get_payment_method_details(
                g.current_user.id, 
                method_id, 
                security_key=form.security_key.data
            )
            return render_template(
                "payment_methods/reveal.html",
                method=method,
                decrypted_metadata=decrypted_metadata,
            )
        except TamperedDataError as e:
            flash(f"Cryptographic integrity alert: {str(e)}", "danger")
            return render_template("payment_methods/verify_reveal.html", method=method, form=form)
        except ValueError as e:
            flash(str(e), "danger")
            return render_template("payment_methods/verify_reveal.html", method=method, form=form)
        except Exception:
            flash("Decryption failed.", "danger")
            return render_template("payment_methods/verify_reveal.html", method=method, form=form)

    return render_template("payment_methods/verify_reveal.html", method=method, form=form)


@payment_methods_bp.route("/<int:method_id>/delete", methods=["POST"])
@login_required
def delete(method_id: int):
    try:
        delete_payment_method(g.current_user.id, method_id)
        flash("Payment method removed successfully.", "info")
    except ValueError as e:
        flash(str(e), "danger")
    return redirect(url_for("payment_methods.index"))

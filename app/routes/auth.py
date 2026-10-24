# User authentication routes handling registration, login, profile management, and logout.
# Verifies salted SHA-256 password credentials and manages authenticated session state.
# Applies sliding-window in-memory rate limiting to defend against brute-force attacks.

from urllib.parse import urlsplit
from flask import Blueprint, flash, redirect, render_template, request, session, url_for, g
from app.extensions import db
from app.models.user import User
from app.forms.auth import RegistrationForm, LoginForm
from app.utils.password_sha256 import hash_password, verify_password
from app.utils.validators import validate_registration
from app.utils.rate_limiter_sliding_window import login_limiter
from app.utils.decorators import login_required
from app.services.wallet_service import create_wallet_for_user

auth_bp = Blueprint("auth", __name__)


def is_safe_redirect_url(target: str) -> bool:
    if not target:
        return False
    target_split = urlsplit(target)
    return target_split.scheme == "" and target_split.netloc == ""


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("auth.dashboard"))

    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        password = form.password.data
        confirm = form.confirm_password.data

        is_valid, validation_err = validate_registration(username, email, password, confirm)
        if not is_valid:
            flash(validation_err, "danger")
            return render_template("auth/register.html", form=form), 400

        if User.query.filter_by(username=username).first():
            flash("Username is already taken. Please choose another.", "danger")
            return render_template("auth/register.html", form=form), 409

        if User.query.filter_by(email=email).first():
            flash("Email address is already registered.", "danger")
            return render_template("auth/register.html", form=form), 409

        user = User(username=username, email=email)
        user.set_password(password)

        db.session.add(user)
        db.session.flush()

        create_wallet_for_user(user_id=user.id, initial_balance_cents=0)

        db.session.commit()

        flash("Account created successfully! You may now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("auth.dashboard"))

    form = LoginForm()
    client_ip = request.remote_addr or "127.0.0.1"

    if form.validate_on_submit():
        identifier = form.username_or_email.data.strip()
        password = form.password.data

        ip_limited, ip_rem = login_limiter.is_rate_limited(client_ip)
        if ip_limited:
            flash(f"Too many failed login attempts. Please try again in {ip_rem} seconds.", "danger")
            return render_template("auth/login.html", form=form), 429

        user_limited, user_rem = login_limiter.is_rate_limited(f"user:{identifier}")
        if user_limited:
            flash(f"Too many failed login attempts for this account. Please wait {user_rem} seconds.", "danger")
            return render_template("auth/login.html", form=form), 429

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if not user or not user.check_password(password):
            login_limiter.record_failed_attempt(client_ip)
            login_limiter.record_failed_attempt(f"user:{identifier}")

            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html", form=form), 401

        if not user.is_active:
            flash("This account has been deactivated. Please contact support.", "danger")
            return render_template("auth/login.html", form=form), 403

        login_limiter.reset(client_ip)
        login_limiter.reset(f"user:{identifier}")

        session.clear()
        session["user_id"] = user.id
        session["username"] = user.username

        flash(f"Welcome back, {user.username}!", "success")

        next_page = request.args.get("next")
        if next_page and is_safe_redirect_url(next_page):
            return redirect(next_page)

        return redirect(url_for("wallet.dashboard"))

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You have been successfully logged out.", "info")
    return redirect(url_for("main.index"))


@auth_bp.route("/dashboard")
@login_required
def dashboard():
    return redirect(url_for("wallet.dashboard"))


@auth_bp.route("/profile")
@login_required
def profile():
    return render_template("auth/profile.html", user=g.current_user)


@auth_bp.after_request
def add_auth_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response

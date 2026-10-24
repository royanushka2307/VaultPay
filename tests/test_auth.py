# Test suite for user authentication, password hashing, and session management.
# Tests per-user salt uniqueness, SHA-256 verification, registration, login, and logout.
# Verifies sliding-window rate limiting on repeated failed login attempts.

import pytest
from app.extensions import db
from app.models.user import User
from app.utils.password_sha256 import generate_salt, hash_password, verify_password
from app.utils.rate_limiter_sliding_window import login_limiter


def test_each_user_gets_a_different_salt():
    salt1 = generate_salt()
    salt2 = generate_salt()

    assert len(salt1) == 64
    assert len(salt2) == 64
    assert salt1 != salt2, "Two generated salts must not be identical!"


def test_same_password_different_salts_produce_different_hashes():
    password = "SuperSecurePassword123!"
    salt_alice = generate_salt()
    salt_bob = generate_salt()

    hash_alice = hash_password(password, salt_alice)
    hash_bob = hash_password(password, salt_bob)

    assert len(hash_alice) == 64
    assert len(hash_bob) == 64
    assert hash_alice != hash_bob, "Hashes for the same password with different salts MUST NOT match!"


def test_incorrect_salt_or_hash_verification_fails():
    password = "CorrectHorseBatteryStaple99"
    real_salt = generate_salt()
    tampered_salt = generate_salt()
    real_hash = hash_password(password, real_salt)

    assert verify_password(password, real_salt, real_hash) is True

    assert verify_password("WrongPassword123", real_salt, real_hash) is False

    assert verify_password(password, tampered_salt, real_hash) is False

    fake_hash = "0" * 64
    assert verify_password(password, real_salt, fake_hash) is False


def test_password_is_not_stored_as_plaintext(app):
    with app.app_context():
        user = User(username="test_student", email="student@example.edu")
        raw_password = "CollegeProjectPassword2026!"
        user.set_password(raw_password)

        assert user.password_hash != raw_password
        assert user.password_salt != raw_password
        assert raw_password not in user.password_hash
        assert raw_password not in user.password_salt
        assert len(user.password_hash) == 64
        assert len(user.password_salt) == 64

        assert user.check_password(raw_password) is True
        assert user.check_password("IncorrectPassword") is False


def test_successful_registration(client, app):
    response = client.post(
        "/register",
        data={
            "username": "alice_smith",
            "email": "alice@college.edu",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    content = response.get_data(as_text=True)
    assert "Account created successfully" in content

    with app.app_context():
        user = User.query.filter_by(username="alice_smith").first()
        assert user is not None
        assert user.email == "alice@college.edu"
        assert user.password_hash is not None
        assert user.password_salt is not None
        assert user.check_password("SecurePassword123!") is True


def test_duplicate_registration(client):
    client.post(
        "/register",
        data={
            "username": "bob_builder",
            "email": "bob@college.edu",
            "password": "BobPassword123!",
            "confirm_password": "BobPassword123!",
        },
    )

    response_dup_user = client.post(
        "/register",
        data={
            "username": "bob_builder",
            "email": "different_bob@college.edu",
            "password": "BobPassword123!",
            "confirm_password": "BobPassword123!",
        },
    )
    assert response_dup_user.status_code == 409
    assert "Username is already taken" in response_dup_user.get_data(as_text=True)

    response_dup_email = client.post(
        "/register",
        data={
            "username": "bob_alternate",
            "email": "bob@college.edu",
            "password": "BobPassword123!",
            "confirm_password": "BobPassword123!",
        },
    )
    assert response_dup_email.status_code == 409
    assert "Email address is already registered" in response_dup_email.get_data(as_text=True)


def test_successful_login_and_session(client):
    client.post(
        "/register",
        data={
            "username": "carol_crypto",
            "email": "carol@college.edu",
            "password": "CarolPassword123!",
            "confirm_password": "CarolPassword123!",
        },
    )

    response = client.post(
        "/login",
        data={
            "username_or_email": "carol_crypto",
            "password": "CarolPassword123!",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    content = response.get_data(as_text=True)
    assert "carol_crypto" in content

    client.get("/logout")
    response_email = client.post(
        "/login",
        data={
            "username_or_email": "carol@college.edu",
            "password": "CarolPassword123!",
        },
        follow_redirects=True,
    )
    assert response_email.status_code == 200
    assert "carol_crypto" in response_email.get_data(as_text=True)


def test_incorrect_password(client):
    client.post(
        "/register",
        data={
            "username": "dave_dev",
            "email": "dave@college.edu",
            "password": "DavePassword123!",
            "confirm_password": "DavePassword123!",
        },
    )

    response = client.post(
        "/login",
        data={
            "username_or_email": "dave_dev",
            "password": "CompletelyWrongPassword!",
        },
    )
    assert response.status_code == 401
    assert "Invalid username or password" in response.get_data(as_text=True)

    response_nonexistent = client.post(
        "/login",
        data={
            "username_or_email": "ghost_user",
            "password": "DavePassword123!",
        },
    )
    assert response_nonexistent.status_code == 401
    assert "Invalid username or password" in response_nonexistent.get_data(as_text=True)


def test_logout(client):
    client.post(
        "/register",
        data={
            "username": "eve_eavesdropper",
            "email": "eve@college.edu",
            "password": "EvePassword123!",
            "confirm_password": "EvePassword123!",
        },
    )
    client.post(
        "/login",
        data={
            "username_or_email": "eve_eavesdropper",
            "password": "EvePassword123!",
        },
    )

    resp = client.get("/dashboard", follow_redirects=True)
    assert resp.status_code == 200

    logout_resp = client.get("/logout", follow_redirects=True)
    assert logout_resp.status_code == 200
    assert "You have been successfully logged out" in logout_resp.get_data(as_text=True)

    dash_after = client.get("/dashboard")
    assert dash_after.status_code == 302
    assert "/login" in dash_after.headers["Location"]


def test_protected_route_without_authentication(client):
    response = client.get("/dashboard", follow_redirects=True)
    assert response.status_code == 200
    content = response.get_data(as_text=True)
    assert "Please log in to access this page" in content
    assert "Sign In" in content


def test_login_rate_limiting(client):
    client.post(
        "/register",
        data={
            "username": "frank_target",
            "email": "frank@college.edu",
            "password": "FrankPassword123!",
            "confirm_password": "FrankPassword123!",
        },
    )

    for _ in range(5):
        resp = client.post(
            "/login",
            data={
                "username_or_email": "frank_target",
                "password": "WrongPasswordAttempt!",
            },
        )
        assert resp.status_code == 401

    resp_blocked = client.post(
        "/login",
        data={
            "username_or_email": "frank_target",
            "password": "WrongPasswordAttempt!",
        },
    )
    assert resp_blocked.status_code == 429
    assert "Too many failed login attempts" in resp_blocked.get_data(as_text=True)


def test_algorithmic_module_naming_and_compatibility():
    import app.utils.password_sha256 as explicit_sha
    import app.utils.password as shim_sha
    import app.utils.rate_limiter_sliding_window as explicit_rl
    import app.utils.rate_limiter as shim_rl
    import app.utils.money_integer_cents as explicit_money
    import app.utils.money as shim_money

    assert explicit_sha.generate_salt is shim_sha.generate_salt
    assert explicit_sha.hash_password is shim_sha.hash_password
    assert explicit_sha.verify_password is shim_sha.verify_password

    assert explicit_rl.LoginRateLimiter is shim_rl.LoginRateLimiter
    assert explicit_rl.login_limiter is shim_rl.login_limiter

    assert explicit_money.parse_amount_to_cents is shim_money.parse_amount_to_cents
    assert explicit_money.format_cents is shim_money.format_cents

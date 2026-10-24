# End-to-end integration test suite simulating full user journeys and security scenarios.
# Tests user onboarding, wallet operations, payment methods, and error page rendering.
# Verifies navigation link integrity and audits application responses for data leakage.

import re
from urllib.parse import urlparse
import pytest
from flask import g
from app.extensions import db
from app.models.user import User
from app.models.wallet import Wallet
from app.models.payment_method import PaymentMethod
from app.models.card import DemoCard
from app.services.payment_method_service import create_payment_method
from app.services.card_service import create_demo_card


LINK_PATTERN = re.compile(r'(?:href|action)=["\'](/[^"\']*)["\']', re.IGNORECASE)


def extract_internal_links(html: str) -> set[str]:
    links = set()
    for match in LINK_PATTERN.findall(html):
        parsed = urlparse(match)
        path = parsed.path
        if (
            path
            and not path.startswith("/static/")
            and not path.startswith("#")
            and not path.startswith("javascript:")
        ):
            links.add(path)
    return links


def test_e2e_complete_positive_user_flow(client, app):
    reg_resp = client.post(
        "/register",
        data={
            "username": "Alice",
            "email": "alice@college.edu",
            "password": "AliceSecurePass123!",
            "confirm_password": "AliceSecurePass123!",
        },
        follow_redirects=True,
    )
    assert reg_resp.status_code == 200
    assert "Account created successfully" in reg_resp.get_data(as_text=True)

    login_resp = client.post(
        "/login",
        data={
            "username_or_email": "Alice",
            "password": "AliceSecurePass123!",
        },
        follow_redirects=True,
    )
    assert login_resp.status_code == 200
    alice_dash = login_resp.get_data(as_text=True)
    assert "Welcome back, Alice" in alice_dash
    assert "₹0.00" in alice_dash

    deposit_resp = client.post(
        "/wallet/deposit",
        data={
            "amount": "150.00",
            "description": "College Grant",
        },
        follow_redirects=True,
    )
    assert deposit_resp.status_code == 200
    deposit_html = deposit_resp.get_data(as_text=True)
    assert "deposit of ₹150.00 completed successfully" in deposit_html.lower()
    assert "₹150.00" in deposit_html

    pm_resp = client.post(
        "/payment-methods/new",
        data={
            "method_type": "DEMO_VISA",
            "name": "Alice Student Visa",
            "last_four": "4242",
            "security_key": "1234",
            "demo_metadata": "Card Exp: 12/28",
            "is_default": "y",
        },
        follow_redirects=True,
    )
    assert pm_resp.status_code == 200
    pm_html = pm_resp.get_data(as_text=True)
    assert "Payment method added successfully" in pm_html
    assert "Alice Student Visa" in pm_html
    assert "**** **** **** 4242" in pm_html

    dash_resp = client.get("/wallet/dashboard")
    assert dash_resp.status_code == 200
    dash_html = dash_resp.get_data(as_text=True)
    assert "₹150.00" in dash_html
    assert "College Grant" in dash_html

    client.get("/logout")
    bob_reg = client.post(
        "/register",
        data={
            "username": "Bob",
            "email": "bob@college.edu",
            "password": "BobSecurePass456!",
            "confirm_password": "BobSecurePass456!",
        },
        follow_redirects=True,
    )
    assert bob_reg.status_code == 200
    assert "Account created successfully" in bob_reg.get_data(as_text=True)

    client.post(
        "/login",
        data={
            "username_or_email": "Alice",
            "password": "AliceSecurePass123!",
        },
        follow_redirects=True,
    )

    transfer_resp = client.post(
        "/wallet/transfer",
        data={
            "recipient": "Bob",
            "amount": "40.00",
            "note": "Split lab textbook expenses",
        },
        follow_redirects=True,
    )
    assert transfer_resp.status_code == 200
    transfer_html = transfer_resp.get_data(as_text=True)
    assert "Successfully sent ₹40.00 to @Bob" in transfer_html
    assert "₹110.00" in transfer_html

    alice_hist = client.get("/wallet/history")
    assert alice_hist.status_code == 200
    alice_hist_html = alice_hist.get_data(as_text=True)
    assert "-₹40.00" in alice_hist_html
    assert "Bob" in alice_hist_html
    assert "Split lab textbook expenses" in alice_hist_html

    client.get("/logout")
    bob_login = client.post(
        "/login",
        data={
            "username_or_email": "Bob",
            "password": "BobSecurePass456!",
        },
        follow_redirects=True,
    )
    assert bob_login.status_code == 200
    bob_dash = bob_login.get_data(as_text=True)
    assert "Welcome back, Bob" in bob_dash

    assert "₹40.00" in bob_dash

    bob_hist = client.get("/wallet/history")
    assert bob_hist.status_code == 200
    bob_hist_html = bob_hist.get_data(as_text=True)
    assert "+₹40.00" in bob_hist_html
    assert "Alice" in bob_hist_html
    assert "Split lab textbook expenses" in bob_hist_html

    logout_resp = client.get("/logout", follow_redirects=True)
    assert logout_resp.status_code == 200
    assert "successfully logged out" in logout_resp.get_data(as_text=True).lower()

    protected_urls = [
        "/wallet/dashboard",
        "/wallet/deposit",
        "/wallet/transfer",
        "/wallet/history",
        "/payment-methods",
        "/payment-methods/new",
        "/profile",
        "/cards",
        "/cards/new",
        "/dashboard",
    ]
    for url in protected_urls:
        resp = client.get(url, follow_redirects=False)
        assert resp.status_code == 302, f"Expected 302 redirect for {url}, got {resp.status_code}"
        assert "/login" in resp.headers["Location"], f"Expected redirect to /login for {url}"


def test_e2e_invalid_and_security_cases(client, app):
    client.post(
        "/register",
        data={
            "username": "Alice",
            "email": "alice@college.edu",
            "password": "AliceSecurePass123!",
            "confirm_password": "AliceSecurePass123!",
        },
    )
    client.post(
        "/register",
        data={
            "username": "Bob",
            "email": "bob@college.edu",
            "password": "BobSecurePass456!",
            "confirm_password": "BobSecurePass456!",
        },
    )

    wrong_pw_resp = client.post(
        "/login",
        data={
            "username_or_email": "Alice",
            "password": "IncorrectPassword999!",
        },
    )
    assert wrong_pw_resp.status_code == 401
    assert "Invalid username or password" in wrong_pw_resp.get_data(as_text=True)

    client.post(
        "/login",
        data={
            "username_or_email": "Alice",
            "password": "AliceSecurePass123!",
        },
    )
    client.post("/wallet/deposit", data={"amount": "50.00", "description": "Initial Fund"})

    zero_dep = client.post("/wallet/deposit", data={"amount": "0.00"})
    assert zero_dep.status_code == 400
    assert "greater than zero" in zero_dep.get_data(as_text=True)

    neg_dep = client.post("/wallet/deposit", data={"amount": "-25.00"})
    assert neg_dep.status_code == 400
    assert "greater than zero" in neg_dep.get_data(as_text=True)

    bad_dep = client.post("/wallet/deposit", data={"amount": "one_hundred"})
    assert bad_dep.status_code == 400
    assert "Invalid amount format" in bad_dep.get_data(as_text=True)

    fractional_dep = client.post("/wallet/deposit", data={"amount": "10.555"})
    assert fractional_dep.status_code == 400
    assert "cannot have more than 2 decimal places" in fractional_dep.get_data(as_text=True)

    zero_tx = client.post("/wallet/transfer", data={"recipient": "Bob", "amount": "0.00"})
    assert zero_tx.status_code == 400
    assert "greater than zero" in zero_tx.get_data(as_text=True)

    neg_tx = client.post("/wallet/transfer", data={"recipient": "Bob", "amount": "-15.00"})
    assert neg_tx.status_code == 400
    assert "greater than zero" in neg_tx.get_data(as_text=True)

    bad_tx = client.post("/wallet/transfer", data={"recipient": "Bob", "amount": "abc"})
    assert bad_tx.status_code == 400
    assert "Invalid amount format" in bad_tx.get_data(as_text=True)

    insufficient_tx = client.post(
        "/wallet/transfer",
        data={"recipient": "Bob", "amount": "100.00", "note": "Too much money"},
    )
    assert insufficient_tx.status_code == 400
    assert "Insufficient balance" in insufficient_tx.get_data(as_text=True)

    dash_check = client.get("/wallet/dashboard")
    assert "₹50.00" in dash_check.get_data(as_text=True)

    unknown_tx = client.post(
        "/wallet/transfer",
        data={"recipient": "NonExistentUser123", "amount": "10.00"},
    )
    assert unknown_tx.status_code == 400
    assert "not found" in unknown_tx.get_data(as_text=True)

    self_tx = client.post(
        "/wallet/transfer",
        data={"recipient": "Alice", "amount": "10.00"},
    )
    assert self_tx.status_code == 400
    assert "cannot transfer money to yourself" in self_tx.get_data(as_text=True)

    with app.app_context():
        alice = User.query.filter_by(username="Alice").first()
        bob = User.query.filter_by(username="Bob").first()
        alice_pm = create_payment_method(
            user_id=alice.id,
            method_type="DEMO_VISA",
            name="Alice Secret Card",
            last_four="9999",
            metadata="Alice Private Secret Data",
        )
        alice_card = create_demo_card(
            user_id=alice.id,
            cardholder_name="Alice Student",
            last_four="8888",
            card_brand="Visa",
            exp_month=11,
            exp_year=2028,
            billing_details="123 Alice St",
        )
        alice_pm_id = alice_pm.id
        alice_card_id = alice_card.id

    client.get("/logout")
    client.post(
        "/login",
        data={
            "username_or_email": "Bob",
            "password": "BobSecurePass456!",
        },
    )

    pm_reveal = client.get(f"/payment-methods/{alice_pm_id}/reveal", follow_redirects=True)
    assert "Alice Private Secret Data" not in pm_reveal.get_data(as_text=True)
    assert "not authorized" in pm_reveal.get_data(as_text=True).lower() or pm_reveal.status_code == 403

    pm_del = client.post(f"/payment-methods/{alice_pm_id}/delete", follow_redirects=True)
    assert "not authorized" in pm_del.get_data(as_text=True).lower()

    with app.app_context():
        pm_still_exists = PaymentMethod.query.filter_by(id=alice_pm_id).first()
        assert pm_still_exists is not None

    card_reveal = client.get(f"/cards/{alice_card_id}/reveal", follow_redirects=True)
    assert "123 Alice St" not in card_reveal.get_data(as_text=True)
    assert "not authorized" in card_reveal.get_data(as_text=True).lower() or card_reveal.status_code == 403

    card_del = client.post(f"/cards/{alice_card_id}/delete", follow_redirects=True)
    assert "not authorized" in card_del.get_data(as_text=True).lower()

    with app.app_context():
        card_still_exists = DemoCard.query.filter_by(id=alice_card_id).first()
        assert card_still_exists is not None


def test_e2e_link_integrity_and_page_crawl(client, app):
    client.post(
        "/register",
        data={
            "username": "CrawlerUser",
            "email": "crawler@college.edu",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    )
    client.post(
        "/login",
        data={
            "username_or_email": "CrawlerUser",
            "password": "Password123!",
        },
    )

    seed_urls = [
        "/",
        "/health",
        "/wallet/dashboard",
        "/wallet/deposit",
        "/wallet/transfer",
        "/wallet/history",
        "/payment-methods",
        "/payment-methods/new",
        "/cards",
        "/cards/new",
        "/profile",
    ]

    discovered_links = set(seed_urls)

    for url in seed_urls:
        resp = client.get(url)
        assert resp.status_code in (200, 302, 308), f"Seed page {url} returned {resp.status_code}"
        if resp.status_code == 200:
            html = resp.get_data(as_text=True)
            page_links = extract_internal_links(html)
            discovered_links.update(page_links)

    for link in discovered_links:
        if "<" in link or "/delete" in link or link in ("/logout", "/register", "/login"):
            continue

        resp = client.get(link, follow_redirects=False)
        assert resp.status_code in (200, 302, 308), (
            f"Broken link detected: {link} returned HTTP {resp.status_code}"
        )


def test_e2e_data_exposure_audit(client, app):
    password = "SensitiveSuperPassword987!"
    client.post(
        "/register",
        data={
            "username": "AuditUser",
            "email": "audit@college.edu",
            "password": password,
            "confirm_password": password,
        },
    )
    client.post(
        "/login",
        data={
            "username_or_email": "AuditUser",
            "password": password,
        },
    )

    with app.app_context():
        user = User.query.filter_by(username="AuditUser").first()
        password_hash = user.password_hash
        password_salt = user.password_salt
        encryption_key = app.config.get("ENCRYPTION_KEY", "")

    pages_to_audit = [
        "/",
        "/health",
        "/wallet/dashboard",
        "/wallet/deposit",
        "/wallet/transfer",
        "/wallet/history",
        "/payment-methods",
        "/payment-methods/new",
        "/cards",
        "/cards/new",
        "/profile",
    ]

    for page in pages_to_audit:
        resp = client.get(page)
        if resp.status_code == 200:
            html = resp.get_data(as_text=True)

            assert password not in html, f"LEAK ALERT: Plaintext password leaked on {page}!"

            assert password_hash not in html, f"LEAK ALERT: Password hash leaked on {page}!"

            assert password_salt not in html, f"LEAK ALERT: Password salt leaked on {page}!"

            if encryption_key:
                assert encryption_key not in html, f"LEAK ALERT: Encryption key leaked on {page}!"

# Test suite for polymorphic chameleon virtual cards and canary tripwires.
# Verifies single-use card morphing, decoy probe interception, and automated vault quarantine.
# Tests incident resolution flows and HTTP workflow endpoints for chameleon card labs.

import pytest
from app.extensions import db
from app.models.user import User
from app.models.wallet import Wallet
from app.models.chameleon_card import ChameleonCard, CanaryIncident
from app.services.chameleon_service import (
    create_chameleon_card,
    simulate_legitimate_purchase,
    simulate_adversary_probe,
    resolve_canary_incident,
    get_chameleon_card_by_id,
    reset_or_create_demo_chameleon,
)


def _create_test_user_and_wallet(app, username="chameleon_user", balance_cents=250000):
    with app.app_context():
        user = User(username=username, email=f"{username}@example.com")
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.flush()

        wallet = Wallet(user_id=user.id, balance_cents=balance_cents, currency="INR")
        db.session.add(wallet)
        db.session.commit()
        return user.id


def test_chameleon_card_provisioning(app):
    user_id = _create_test_user_and_wallet(app)

    with app.app_context():
        card = create_chameleon_card(
            user_id=user_id,
            card_name="AudioGear Order #104",
            merchant_tag="AudioGearShop.in",
            spend_limit_cents=149900
        )

        assert card.id is not None
        assert card.user_id == user_id
        assert card.merchant_tag == "AudioGearShop.in"
        assert card.state == "ACTIVE_BURNER"
        assert card.is_canary is False
        assert card.initial_spend_limit_cents == 149900
        assert card.remaining_balance_cents == 149900
        assert card.spent_amount_cents == 0
        assert card.card_token.startswith("chm_tok_")
        assert "4532" in card.masked_pan


def test_legitimate_purchase_atomically_debits_and_morphs_to_canary(app):
    user_id = _create_test_user_and_wallet(app, balance_cents=250000)

    with app.app_context():
        card = create_chameleon_card(
            user_id=user_id,
            card_name="AudioGear Order #104",
            merchant_tag="AudioGearShop.in",
            spend_limit_cents=149900
        )

        result = simulate_legitimate_purchase(card.id, user_id, 149900)

        assert result["status"] == "SUCCESS"
        assert result["wallet_balance"] == "₹1,001.00"

        db_card = db.session.get(ChameleonCard, card.id)
        assert db_card.state == "ARMED_CANARY"
        assert db_card.is_canary is True
        assert db_card.remaining_balance_cents == 0
        assert db_card.spent_amount_cents == 149900
        assert db_card.morphed_at is not None

        wallet = Wallet.query.filter_by(user_id=user_id).first()
        assert wallet.balance_cents == 100100


def test_cannot_make_secondary_purchase_on_morphed_card(app):
    user_id = _create_test_user_and_wallet(app, balance_cents=250000)

    with app.app_context():
        card = create_chameleon_card(
            user_id=user_id,
            card_name="Test Card",
            merchant_tag="Shop.in",
            spend_limit_cents=50000
        )
        simulate_legitimate_purchase(card.id, user_id, 50000)

        with pytest.raises(ValueError, match="Card cannot make purchases in state: ARMED_CANARY"):
            simulate_legitimate_purchase(card.id, user_id, 50000)


def test_adversary_probe_intercepted_and_quarantines_vault(app):
    user_id = _create_test_user_and_wallet(app, balance_cents=250000)

    with app.app_context():
        card = create_chameleon_card(
            user_id=user_id,
            card_name="Breached Store",
            merchant_tag="CompromisedMerchant.com",
            spend_limit_cents=100000
        )
        simulate_legitimate_purchase(card.id, user_id, 100000)

        probe_result = simulate_adversary_probe(
            card_id=card.id,
            user_id=user_id,
            attacker_ip="185.220.101.5",
            user_agent="python-requests/2.31.0 - Automated Bot",
            probe_amount_cents=100
        )

        assert probe_result["status"] == "TRIPWIRE_TRIGGERED"
        assert probe_result["user_security_status"] == "QUARANTINED"
        assert probe_result["tarpit_response"]["http_status"] == 200
        assert probe_result["tarpit_response"]["simulated_delay_ms"] == 1200
        assert probe_result["tarpit_response"]["payload"]["code"] == "insufficient_funds"

        db_card = db.session.get(ChameleonCard, card.id)
        assert db_card.state == "TRIPPED"
        assert db_card.tripped_at is not None

        incident = CanaryIncident.query.filter_by(card_id=card.id).first()
        assert incident is not None
        assert incident.attacker_ip == "185.220.101.5"
        assert "Tor Exit Relay" in incident.attacker_geo
        assert incident.resolved is False

        user = db.session.get(User, user_id)
        assert user.security_status == "QUARANTINED"


def test_resolve_canary_incident_restores_vault_status(app):
    user_id = _create_test_user_and_wallet(app, balance_cents=250000)

    with app.app_context():
        card = create_chameleon_card(
            user_id=user_id,
            card_name="Breached Store",
            merchant_tag="Store.com",
            spend_limit_cents=100000
        )
        simulate_legitimate_purchase(card.id, user_id, 100000)
        simulate_adversary_probe(card.id, user_id)

        user = db.session.get(User, user_id)
        assert user.security_status == "QUARANTINED"

        resolve_result = resolve_canary_incident(card.id, user_id)
        assert resolve_result["status"] == "RESOLVED"
        assert resolve_result["user_security_status"] == "NORMAL"

        db_card = db.session.get(ChameleonCard, card.id)
        assert db_card.state == "NEUTRALIZED"

        user = db.session.get(User, user_id)
        assert user.security_status == "NORMAL"


def test_unauthenticated_access_to_chameleon_lab_redirects(client):
    response = client.get("/chameleon-simulator", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_chameleon_lab_full_http_workflow(app, client):
    client.post("/register", data={
        "username": "chameleon_tester",
        "email": "chameleon_tester@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!",
    }, follow_redirects=True)

    client.post("/login", data={
        "username_or_email": "chameleon_tester",
        "password": "Password123!",
    }, follow_redirects=True)

    client.post("/wallet/deposit", data={
        "amount": "2500.00",
    }, follow_redirects=True)

    get_resp = client.get("/chameleon-simulator")
    assert get_resp.status_code == 200
    assert b"CHAMELEON CARD" in get_resp.data
    assert b"CANARY TRIPWIRE" in get_resp.data

    with app.app_context():
        user = User.query.filter_by(username="chameleon_tester").first()
        cards = ChameleonCard.query.filter_by(user_id=user.id).all()
        assert len(cards) > 0
        card_id = cards[0].id

    purchase_resp = client.post("/chameleon-simulator/api/purchase", json={
        "card_id": card_id
    })
    assert purchase_resp.status_code == 200
    p_data = purchase_resp.get_json()
    assert p_data["success"] is True
    assert p_data["card"]["state"] == "ARMED_CANARY"

    probe_resp = client.post("/chameleon-simulator/api/probe", json={
        "card_id": card_id,
        "attacker_ip": "185.220.101.5"
    })
    assert probe_resp.status_code == 200
    pr_data = probe_resp.get_json()
    assert pr_data["success"] is True
    assert pr_data["status"] == "TRIPWIRE_TRIGGERED"
    assert pr_data["user_security_status"] == "QUARANTINED"

    dash_resp = client.get("/wallet/dashboard")
    assert dash_resp.status_code == 200
    assert b"VAULT IN PROTECTIVE QUARANTINE" in dash_resp.data

    resolve_resp = client.post("/chameleon-simulator/api/resolve", json={
        "card_id": card_id
    })
    assert resolve_resp.status_code == 200
    r_data = resolve_resp.get_json()
    assert r_data["success"] is True
    assert r_data["card"]["state"] == "NEUTRALIZED"
    assert r_data["user_security_status"] == "NORMAL"

    reset_resp = client.post("/chameleon-simulator/api/reset")
    assert reset_resp.status_code == 200
    reset_data = reset_resp.get_json()
    assert reset_data["success"] is True
    assert reset_data["card"]["state"] == "ACTIVE_BURNER"


def test_custom_chameleon_card_provisioning_and_card_details_api(client):
    client.post("/register", data={
        "username": "custom_card_user",
        "email": "custom_card_user@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!",
    }, follow_redirects=True)

    client.post("/login", data={
        "username_or_email": "custom_card_user",
        "password": "Password123!",
    }, follow_redirects=True)

    create_resp = client.post("/chameleon-simulator/api/create-card", json={
        "card_name": "ShadyElectronics Flash Deal",
        "merchant_tag": "ShadyElectronics.in",
        "spend_limit": "750.50",
    })
    assert create_resp.status_code == 200
    create_data = create_resp.get_json()
    assert create_data["success"] is True
    card = create_data["card"]
    assert card["card_name"] == "ShadyElectronics Flash Deal"
    assert card["merchant_tag"] == "ShadyElectronics.in"
    assert card["initial_spend_limit_cents"] == 75050
    assert card["state"] == "ACTIVE_BURNER"

    get_card_resp = client.get(f"/chameleon-simulator/api/cards/{card['id']}")
    assert get_card_resp.status_code == 200
    gcd = get_card_resp.get_json()
    assert gcd["success"] is True
    assert gcd["card"]["id"] == card["id"]
    assert gcd["card"]["merchant_tag"] == "ShadyElectronics.in"


def test_payment_methods_page_displays_chameleon_cards(client):
    client.post("/register", data={
        "username": "pm_chameleon_user",
        "email": "pm_chameleon_user@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!",
    }, follow_redirects=True)

    client.post("/login", data={
        "username_or_email": "pm_chameleon_user",
        "password": "Password123!",
    }, follow_redirects=True)

    client.post("/chameleon-simulator/api/create-card", json={
        "card_name": "NordVPN 1-Yr Promo",
        "merchant_tag": "NordVPN.com",
        "spend_limit": "2499.00",
    })

    pm_resp = client.get("/payment-methods")
    assert pm_resp.status_code == 200
    assert b"Chameleon Virtual Cards" in pm_resp.data
    assert b"Issue Chameleon Card" in pm_resp.data
    assert b"NordVPN 1-Yr Promo" in pm_resp.data
    assert b"NordVPN.com" in pm_resp.data

# Test suite for digital wallet operations, integer balance calculations, and transactions.
# Tests automatic wallet creation, fund deposits, peer-to-peer transfers, and atomic rollbacks.
# Verifies transaction history retrieval, individual transaction deletion, and IDOR defenses.

import pytest
from app.extensions import db
from app.models.user import User
from app.models.wallet import Wallet
from app.models.transaction import Transaction
from app.services.wallet_service import deposit_funds, get_or_create_user_wallet


def register_and_login(client, username="alice_wallet", email="alice@wallet.edu", password="Password123!"):
    client.post(
        "/register",
        data={
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password,
        },
    )
    client.post(
        "/login",
        data={
            "username_or_email": username,
            "password": password,
        },
    )


def test_automatic_wallet_creation_on_registration(client, app):
    client.post(
        "/register",
        data={
            "username": "new_user",
            "email": "new_user@college.edu",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
    )

    with app.app_context():
        user = User.query.filter_by(username="new_user").first()
        assert user is not None
        assert user.wallet is not None
        assert user.wallet.balance_cents == 0
        assert user.wallet.currency == "INR"
        assert user.wallet.formatted_balance == "₹0.00"


def test_successful_deposit(client, app):
    register_and_login(client, username="depositor_1", email="dep1@college.edu")

    response = client.post(
        "/wallet/deposit",
        data={"amount": "50.25", "description": "Pocket money"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    content = response.get_data(as_text=True)
    assert "Deposit of ₹50.25 completed successfully" in content
    assert "₹50.25" in content

    with app.app_context():
        user = User.query.filter_by(username="depositor_1").first()
        assert user.wallet.balance_cents == 5025
        assert user.wallet.formatted_balance == "₹50.25"


def test_invalid_deposit_zero_and_negative(client, app):
    register_and_login(client, username="zero_tester", email="zero@college.edu")

    res_zero = client.post(
        "/wallet/deposit",
        data={"amount": "0.00", "description": "Zero deposit"},
    )
    assert res_zero.status_code == 400
    assert "Amount must be strictly greater than zero" in res_zero.get_data(as_text=True)

    res_neg = client.post(
        "/wallet/deposit",
        data={"amount": "-25.00", "description": "Negative deposit"},
    )
    assert res_neg.status_code == 400
    assert "Amount must be strictly greater than zero" in res_neg.get_data(as_text=True)

    with app.app_context():
        user = User.query.filter_by(username="zero_tester").first()
        assert user.wallet.balance_cents == 0


def test_invalid_deposit_malformed_formats(client, app):
    register_and_login(client, username="format_tester", email="fmt@college.edu")

    res_text = client.post(
        "/wallet/deposit",
        data={"amount": "fifty_dollars"},
    )
    assert res_text.status_code == 400
    assert "Invalid amount format" in res_text.get_data(as_text=True)

    res_subcents = client.post(
        "/wallet/deposit",
        data={"amount": "10.999"},
    )
    assert res_subcents.status_code == 400
    assert "cannot have more than 2 decimal places" in res_subcents.get_data(as_text=True)

    res_overflow = client.post(
        "/wallet/deposit",
        data={"amount": "10000000.01"},
    )
    assert res_overflow.status_code == 400
    assert "cannot exceed ₹10,000,000.00" in res_overflow.get_data(as_text=True)


def test_integer_arithmetic_eliminates_floating_point_rounding_error(client, app):
    register_and_login(client, username="float_tester", email="float@college.edu")

    client.post("/wallet/deposit", data={"amount": "0.10"})
    client.post("/wallet/deposit", data={"amount": "0.20"})

    with app.app_context():
        user = User.query.filter_by(username="float_tester").first()
        assert user.wallet.balance_cents == 30
        assert user.wallet.formatted_balance == "₹0.30"


def test_unauthorized_wallet_access_requires_login(client):
    res_dash = client.get("/wallet/dashboard")
    assert res_dash.status_code == 302
    assert "/login" in res_dash.headers["Location"]

    res_dep = client.get("/wallet/deposit")
    assert res_dep.status_code == 302
    assert "/login" in res_dep.headers["Location"]

    res_hist = client.get("/wallet/history")
    assert res_hist.status_code == 302
    assert "/login" in res_hist.headers["Location"]


def test_users_can_access_only_their_own_wallet(client, app):
    register_and_login(client, username="user_alice", email="alice@test.edu")
    client.post("/wallet/deposit", data={"amount": "100.00"})
    client.get("/logout")

    register_and_login(client, username="user_bob", email="bob@test.edu")
    client.post("/wallet/deposit", data={"amount": "25.00"})

    res_bob = client.get("/wallet/dashboard")
    content_bob = res_bob.get_data(as_text=True)
    assert "₹25.00" in content_bob
    assert "₹100.00" not in content_bob

    with app.app_context():
        alice = User.query.filter_by(username="user_alice").first()
        bob = User.query.filter_by(username="user_bob").first()
        assert alice.wallet.balance_cents == 10000
        assert bob.wallet.balance_cents == 2500
        assert alice.wallet.id != bob.wallet.id


def test_transaction_creation_and_attributes(client, app):
    register_and_login(client, username="ledger_user", email="ledger@test.edu")

    client.post(
        "/wallet/deposit",
        data={"amount": "75.50", "description": "Gift"},
    )

    with app.app_context():
        user = User.query.filter_by(username="ledger_user").first()
        txs = user.wallet.transactions.all()
        assert len(txs) == 1

        tx = txs[0]
        assert tx.amount_cents == 7550
        assert tx.formatted_amount == "₹75.50"
        assert tx.transaction_type == "DEPOSIT"
        assert tx.status == "COMPLETED"
        assert tx.description == "Gift"
        assert len(tx.reference_id) == 36
        assert tx.wallet_id == user.wallet.id


def test_transaction_history_endpoint(client):
    register_and_login(client, username="history_user", email="hist@test.edu")

    client.post("/wallet/deposit", data={"amount": "10.00", "description": "Deposit 1"})
    client.post("/wallet/deposit", data={"amount": "20.00", "description": "Deposit 2"})

    response = client.get("/wallet/history")
    assert response.status_code == 200
    content = response.get_data(as_text=True)
    assert "+₹10.00" in content
    assert "+₹20.00" in content
    assert "Deposit 1" in content
    assert "Deposit 2" in content
    assert "COMPLETED" in content


def test_successful_transfer(client, app):
    register_and_login(client, username="alice_sender", email="alice_s@test.edu")
    client.post("/wallet/deposit", data={"amount": "100.00"})
    client.get("/logout")

    register_and_login(client, username="bob_receiver", email="bob_r@test.edu")
    client.get("/logout")

    client.post(
        "/login",
        data={"username_or_email": "alice_sender", "password": "Password123!"},
    )
    res_transfer = client.post(
        "/wallet/transfer",
        data={
            "recipient": "bob_receiver",
            "amount": "40.00",
            "note": "Coffee and donuts",
        },
        follow_redirects=True,
    )
    assert res_transfer.status_code == 200
    content = res_transfer.get_data(as_text=True)
    assert "Successfully sent ₹40.00 to @bob_receiver" in content
    assert "₹60.00" in content

    with app.app_context():
        alice = User.query.filter_by(username="alice_sender").first()
        bob = User.query.filter_by(username="bob_receiver").first()

        assert alice.wallet.balance_cents == 6000
        assert bob.wallet.balance_cents == 4000

        alice_txs = alice.wallet.transactions.all()
        assert len(alice_txs) == 2
        tx_out = [t for t in alice_txs if t.transaction_type == "TRANSFER_OUT"][0]
        assert tx_out.amount_cents == -4000
        assert tx_out.formatted_amount == "-₹40.00"
        assert "@bob_receiver" in tx_out.description
        assert "Coffee and donuts" in tx_out.description
        assert tx_out.status == "COMPLETED"

        bob_txs = bob.wallet.transactions.all()
        assert len(bob_txs) == 1
        tx_in = bob_txs[0]
        assert tx_in.amount_cents == 4000
        assert tx_in.formatted_amount == "₹40.00"
        assert "@alice_sender" in tx_in.description
        assert "Coffee and donuts" in tx_in.description
        assert tx_in.status == "COMPLETED"


def test_transfer_unknown_recipient(client, app):
    register_and_login(client, username="sender_x", email="sx@test.edu")
    client.post("/wallet/deposit", data={"amount": "50.00"})

    response = client.post(
        "/wallet/transfer",
        data={
            "recipient": "non_existent_user_999",
            "amount": "25.00",
        },
    )
    assert response.status_code == 400
    assert "was not found" in response.get_data(as_text=True)

    with app.app_context():
        user = User.query.filter_by(username="sender_x").first()
        assert user.wallet.balance_cents == 5000


def test_transfer_insufficient_balance(client, app):
    register_and_login(client, username="alice_poor", email="poor@test.edu")
    client.post("/wallet/deposit", data={"amount": "10.00"})
    client.get("/logout")

    register_and_login(client, username="bob_target", email="btarget@test.edu")
    client.get("/logout")

    client.post(
        "/login",
        data={"username_or_email": "alice_poor", "password": "Password123!"},
    )
    response = client.post(
        "/wallet/transfer",
        data={"recipient": "bob_target", "amount": "50.00"},
    )
    assert response.status_code == 400
    assert "Insufficient balance" in response.get_data(as_text=True)

    with app.app_context():
        alice = User.query.filter_by(username="alice_poor").first()
        bob = User.query.filter_by(username="bob_target").first()
        assert alice.wallet.balance_cents == 1000
        assert bob.wallet.balance_cents == 0


def test_transfer_zero_and_negative_amount(client, app):
    register_and_login(client, username="alice_amounts", email="amounts@test.edu")
    client.post("/wallet/deposit", data={"amount": "50.00"})
    client.get("/logout")

    register_and_login(client, username="bob_amounts", email="bamounts@test.edu")
    client.get("/logout")

    client.post(
        "/login",
        data={"username_or_email": "alice_amounts", "password": "Password123!"},
    )

    res_zero = client.post(
        "/wallet/transfer",
        data={"recipient": "bob_amounts", "amount": "0.00"},
    )
    assert res_zero.status_code == 400
    assert "Amount must be strictly greater than zero" in res_zero.get_data(as_text=True)

    res_neg = client.post(
        "/wallet/transfer",
        data={"recipient": "bob_amounts", "amount": "-15.00"},
    )
    assert res_neg.status_code == 400
    assert "Amount must be strictly greater than zero" in res_neg.get_data(as_text=True)

    with app.app_context():
        alice = User.query.filter_by(username="alice_amounts").first()
        assert alice.wallet.balance_cents == 5000


def test_transfer_self_transfer_rejected(client, app):
    register_and_login(client, username="self_sender", email="self@test.edu")
    client.post("/wallet/deposit", data={"amount": "50.00"})

    res_self = client.post(
        "/wallet/transfer",
        data={"recipient": "self_sender", "amount": "10.00"},
    )
    assert res_self.status_code == 400
    assert "cannot transfer money to yourself" in res_self.get_data(as_text=True)

    res_self_email = client.post(
        "/wallet/transfer",
        data={"recipient": "self@test.edu", "amount": "10.00"},
    )
    assert res_self_email.status_code == 400
    assert "cannot transfer money to yourself" in res_self_email.get_data(as_text=True)

    with app.app_context():
        user = User.query.filter_by(username="self_sender").first()
        assert user.wallet.balance_cents == 5000


def test_unauthorized_transaction_access(client, app):
    register_and_login(client, username="alice_priv", email="alice_p@test.edu")
    client.post("/wallet/deposit", data={"amount": "50.00"})
    client.get("/logout")

    register_and_login(client, username="bob_priv", email="bob_p@test.edu")
    client.get("/logout")

    client.post("/login", data={"username_or_email": "alice_priv", "password": "Password123!"})
    client.post("/wallet/transfer", data={"recipient": "bob_priv", "amount": "30.00", "note": "Secret memo 12345"})
    client.get("/logout")

    register_and_login(client, username="charlie_eavesdropper", email="charlie@test.edu")
    res_charlie = client.get("/wallet/history")
    assert res_charlie.status_code == 200
    content = res_charlie.get_data(as_text=True)

    assert "Secret memo 12345" not in content
    assert "bob_priv" not in content
    assert "alice_priv" not in content
    assert "-₹30.00" not in content
    assert "+₹30.00" not in content


def test_transfer_atomic_rollback_on_failure(app):
    from unittest.mock import patch
    from app.services.wallet_service import transfer_funds

    with app.app_context():
        alice = User(username="alice_rollback", email="aroll@test.edu")
        alice.set_password("Password123!")
        db.session.add(alice)
        db.session.flush()

        bob = User(username="bob_rollback", email="broll@test.edu")
        bob.set_password("Password123!")
        db.session.add(bob)
        db.session.flush()

        w_alice = Wallet(user_id=alice.id, balance_cents=5000)
        w_bob = Wallet(user_id=bob.id, balance_cents=0)
        db.session.add_all([w_alice, w_bob])
        db.session.commit()

        with patch.object(db.session, "commit", side_effect=RuntimeError("Simulated Database Crash")):
            with pytest.raises(RuntimeError):
                transfer_funds(
                    sender_user_id=alice.id,
                    recipient_identifier="bob_rollback",
                    amount_cents=2500,
                )

        db.session.rollback()
        db.session.expire_all()

        alice_check = User.query.filter_by(username="alice_rollback").first()
        bob_check = User.query.filter_by(username="bob_rollback").first()

        assert alice_check.wallet.balance_cents == 5000
        assert bob_check.wallet.balance_cents == 0

        txs = Transaction.query.filter(
            Transaction.wallet_id.in_([alice_check.wallet.id, bob_check.wallet.id])
        ).all()
        assert len(txs) == 0


def test_delete_individual_transaction_success(client, app):
    register_and_login(client, username="alice_del_tx", email="alice_del@college.edu")

    client.post("/wallet/deposit", data={"amount": "25.00", "description": "Deposit One"}, follow_redirects=True)
    client.post("/wallet/deposit", data={"amount": "50.00", "description": "Deposit Two"}, follow_redirects=True)

    with app.app_context():
        user = User.query.filter_by(username="alice_del_tx").first()
        txs = Transaction.query.filter_by(wallet_id=user.wallet.id).all()
        assert len(txs) == 2
        tx_to_delete = txs[0]
        tx_to_keep = txs[1]
        target_id = tx_to_delete.id
        keep_id = tx_to_keep.id

    del_res = client.post(f"/wallet/transactions/{target_id}/delete", follow_redirects=True)
    assert del_res.status_code == 200
    assert "Transaction successfully removed from history." in del_res.get_data(as_text=True)

    with app.app_context():
        assert db.session.get(Transaction, target_id) is None
        assert db.session.get(Transaction, keep_id) is not None
        user = User.query.filter_by(username="alice_del_tx").first()
        assert user.wallet.balance_cents == 7500


def test_delete_transaction_idor_defense(client, app):
    with app.app_context():
        bob = User(username="bob_target_tx", email="bob_target@college.edu")
        bob.set_password("Password123!")
        db.session.add(bob)
        db.session.flush()
        w_bob = Wallet(user_id=bob.id, balance_cents=2000)
        db.session.add(w_bob)
        db.session.flush()
        tx_bob = Transaction(
            wallet_id=w_bob.id,
            amount_cents=2000,
            transaction_type="DEPOSIT",
            status="COMPLETED",
            description="Bob Secret Tx",
        )
        db.session.add(tx_bob)
        db.session.commit()
        bob_tx_id = tx_bob.id

    register_and_login(client, username="alice_attacker", email="alice_att@college.edu")

    attack_res = client.post(f"/wallet/transactions/{bob_tx_id}/delete", follow_redirects=True)
    assert attack_res.status_code == 200
    content = attack_res.get_data(as_text=True)
    assert "not authorized" in content or "not found" in content

    with app.app_context():
        check_tx = db.session.get(Transaction, bob_tx_id)
        assert check_tx is not None
        assert check_tx.description == "Bob Secret Tx"


def test_delete_transaction_unauthenticated_redirect(client, app):
    res = client.post("/wallet/transactions/999/delete")
    assert res.status_code == 302
    assert "/login" in res.headers["Location"]

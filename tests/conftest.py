# Pytest configuration and shared test fixtures for the test suite.
# Sets up isolated in-memory SQLite databases, test application instances, and HTTP clients.
# Configures test authentication helpers, session fixtures, and encryption key overrides.

import pytest
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.wallet import Wallet
from app.models.transaction import Transaction
from app.models.card import DemoCard
from app.models.payment_method import PaymentMethod
from app.utils.rate_limiter_sliding_window import login_limiter


@pytest.fixture(scope="session")
def app():
    app = create_app("testing")

    with app.app_context():
        db.create_all()

    yield app

    with app.app_context():
        db.drop_all()


@pytest.fixture(autouse=True)
def reset_test_state(app):
    login_limiter.clear_all()
    with app.app_context():
        db.session.rollback()
        db.session.close()
        db.drop_all()
        db.create_all()
        db.session.remove()
    yield
    login_limiter.clear_all()
    with app.app_context():
        db.session.rollback()
        db.session.close()
        db.session.remove()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()

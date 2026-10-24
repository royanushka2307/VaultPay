# Application configuration classes for development, testing, and production environments.
# Configures database connection URIs, session security parameters, and encryption key paths.
# Provides environment-based configuration lookup mappings and directory definitions.

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-secret-key-change-me")

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {"timeout": 30}
    }

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False

    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")


class DevelopmentConfig(Config):
    DEBUG = True
    default_db_path = (INSTANCE_DIR / "wallet.sqlite").as_posix()
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", 
        f"sqlite:///{default_db_path}"
    )


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

    WTF_CSRF_ENABLED = False

    ENCRYPTION_KEY = os.environ.get(
        "ENCRYPTION_KEY", 
        "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
    )


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

    SESSION_COOKIE_SECURE = True

    default_db_path = (INSTANCE_DIR / "wallet_prod.sqlite").as_posix()
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", 
        f"sqlite:///{default_db_path}"
    )

    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}

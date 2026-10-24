# Core application routes for the homepage, system health check, and crypto architecture.
# Serves public landing pages and authenticated architectural documentation endpoints.

from datetime import datetime, timezone
from flask import Blueprint, jsonify, render_template, redirect, url_for
from sqlalchemy import text

from app.extensions import db
from app.utils.decorators import login_required

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("main/index.html")


@main_bp.route("/crypto-architecture")
@main_bp.route("/architecture")
@login_required
def crypto_architecture():
    return render_template("main/architecture.html")


@main_bp.route("/health")
def health_check():
    db_status = "unknown"
    http_code = 200

    try:
        result = db.session.execute(text("SELECT 1")).scalar()
        if result == 1:
            db_status = "connected"
    except Exception as err:
        db_status = f"disconnected: {str(err)}"
        http_code = 503

    payload = {
        "status": "healthy" if http_code == 200 else "unhealthy",
        "app": "Secure Digital Wallet",
        "mode": "active",
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return jsonify(payload), http_code

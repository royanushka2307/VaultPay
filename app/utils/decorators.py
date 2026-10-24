# Authentication and authorization decorators for protecting Flask routes.
# Validates active user sessions and redirects unauthenticated requests to the login endpoint.

from functools import wraps
from flask import flash, g, redirect, request, session, url_for, jsonify
from app.extensions import db
from app.models.user import User


def login_required(view_function):
    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")

        if not user_id:
            if (
                request.is_json 
                or request.path.startswith("/api/") 
                or request.accept_mimetypes.best == "application/json"
            ):
                return jsonify({"error": "Unauthorized", "message": "Authentication required."}), 401

            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.url))

        user = db.session.get(User, user_id)
        if not user or not user.is_active:
            session.clear()
            flash("Your session is invalid or your account is deactivated. Please log in again.", "danger")
            return redirect(url_for("auth.login"))

        g.current_user = user
        return view_function(*args, **kwargs)

    return decorated_function

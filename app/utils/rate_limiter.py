# Rate limiting facade re-exporting sliding-window memory rate limiting utilities.
# Provides backward-compatible singleton access to login attempt tracking.

from app.utils.rate_limiter_sliding_window import (
    LoginRateLimiter,
    login_limiter,
)

__all__ = [
    "LoginRateLimiter",
    "login_limiter",
]

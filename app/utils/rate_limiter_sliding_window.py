# Sliding-window in-memory rate limiter for authentication endpoints.
# Tracks failed attempt timestamps per client identifier to protect against brute-force attacks.

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from threading import Lock


class LoginRateLimiter:
    def __init__(self, max_attempts: int = 5, lockout_seconds: int = 300):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._attempts = defaultdict(list)
        self._lock = Lock()

    def _clean_expired(self, key: str, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.lockout_seconds)
        self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]

    def is_rate_limited(self, key: str) -> tuple[bool, int]:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._clean_expired(key, now)
            attempts = self._attempts[key]
            if len(attempts) >= self.max_attempts:
                oldest_in_window = attempts[0]
                elapsed = (now - oldest_in_window).total_seconds()
                remaining = max(1, int(self.lockout_seconds - elapsed))
                return True, remaining
            return False, 0

    def record_failed_attempt(self, key: str) -> int:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._clean_expired(key, now)
            self._attempts[key].append(now)
            return len(self._attempts[key])

    def reset(self, key: str) -> None:
        with self._lock:
            if key in self._attempts:
                del self._attempts[key]

    def clear_all(self) -> None:
        with self._lock:
            self._attempts.clear()


login_limiter = LoginRateLimiter(max_attempts=5, lockout_seconds=300)

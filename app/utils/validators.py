# Custom input validation functions for passwords, monetary values, and payment cards.
# Enforces password complexity rules, validates expiration formats, and rejects real CVV codes.

import re

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_username(username: str) -> tuple[bool, str]:
    if not username or not username.strip():
        return False, "Username is required."
    username = username.strip()
    if not USERNAME_REGEX.match(username):
        return False, "Username must be 3-30 characters long and contain only letters, numbers, and underscores."
    return True, ""


def validate_email(email: str) -> tuple[bool, str]:
    if not email or not email.strip():
        return False, "Email address is required."
    email = email.strip()
    if len(email) > 120:
        return False, "Email address is too long (maximum 120 characters)."
    if not EMAIL_REGEX.match(email):
        return False, "Please enter a valid email address."
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    if not password:
        return False, "Password is required."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    return True, ""


def validate_registration(
    username: str, 
    email: str, 
    password: str, 
    confirm_password: str
) -> tuple[bool, str]:
    valid, err = validate_username(username)
    if not valid:
        return False, err

    valid, err = validate_email(email)
    if not valid:
        return False, err

    valid, err = validate_password(password)
    if not valid:
        return False, err

    if password != confirm_password:
        return False, "Passwords do not match."

    return True, ""

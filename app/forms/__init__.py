# Forms package initialization module for the Secure Digital Wallet application.
# Exports WTForms form classes used for user authentication and onboarding.

from app.forms.auth import RegistrationForm, LoginForm

__all__ = ["RegistrationForm", "LoginForm"]

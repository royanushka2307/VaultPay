# Form definition for adding encrypted payment methods such as cards and bank accounts.
# Validates account identifiers, billing details, and ownership credentials.
# Enforces zero-CVV retention by prohibiting CVV submissions on permanent payment methods.

from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, BooleanField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, Regexp, Optional


class PaymentMethodForm(FlaskForm):
    method_type = SelectField(
        "Payment Method Type",
        choices=[
            ("DEMO_VISA", "💳 Visa"),
            ("DEMO_MASTERCARD", "💳 Mastercard"),
            ("DEMO_BANK_ACCOUNT", "🏦 Bank Account"),
        ],
        default="DEMO_VISA",
        validators=[DataRequired()],
    )

    name = StringField(
        "Nickname / Label",
        validators=[
            DataRequired(message="A nickname is required."),
            Length(min=2, max=100, message="Name must be between 2 and 100 characters."),
        ],
        render_kw={"placeholder": "e.g. Primary Savings or Visa Card"},
    )

    last_four = StringField(
        "Last 4 Digits Only",
        validators=[
            DataRequired(message="Last 4 digits are required."),
            Length(min=4, max=4, message="Must be exactly 4 digits."),
            Regexp(r"^\d{4}$", message="Must contain exactly 4 numeric digits."),
        ],
        render_kw={
            "placeholder": "e.g. 4242",
            "maxlength": "4",
            "autocomplete": "off",
            "inputmode": "numeric",
            "pattern": "[0-9]{4}",
            "data-lpignore": "true",
            "data-1p-ignore": "true",
            "data-form-type": "other",
        },
    )

    security_key = PasswordField(
        "4-Digit Security Key (PIN)",
        validators=[
            DataRequired(message="A 4-digit numeric security key is required."),
            Length(min=4, max=4, message="Security key must be exactly 4 digits."),
            Regexp(r"^\d{4}$", message="Security key must contain exactly 4 numeric digits."),
        ],
        render_kw={
            "placeholder": "e.g. 1234",
            "maxlength": "4",
            "autocomplete": "one-time-code",
            "inputmode": "numeric",
            "pattern": "[0-9]{4}",
            "data-lpignore": "true",
            "data-1p-ignore": "true",
            "data-form-type": "other",
        },
    )

    cardholder_name = StringField(
        "Cardholder Name (Optional)",
        validators=[
            Optional(),
            Length(max=100, message="Cardholder name cannot exceed 100 characters."),
        ],
        render_kw={"placeholder": "e.g. Rahul Sharma or Priya Verma"},
    )

    expiry_date = StringField(
        "Card Expiry (Optional)",
        validators=[
            Optional(),
            Length(max=7, message="Expiry must be MM/YY (e.g. 09/29)."),
            Regexp(r"^(0[1-9]|1[0-2])\/\d{2}$|^$", message="Must be MM/YY format (e.g. 08/29)."),
        ],
        render_kw={"placeholder": "MM/YY (e.g. 08/29)", "maxlength": "5"},
    )

    card_network_tier = StringField(
        "Card Product / Tier (Optional)",
        validators=[
            Optional(),
            Length(max=80, message="Card tier cannot exceed 80 characters."),
        ],
        render_kw={"placeholder": "e.g. Visa Infinite, Signature, Platinum, Gold"},
    )

    issuing_bank = StringField(
        "Issuing Bank (Optional)",
        validators=[
            Optional(),
            Length(max=80, message="Bank name cannot exceed 80 characters."),
        ],
        render_kw={"placeholder": "e.g. HDFC Bank, SBI, ICICI Bank, Axis Bank"},
    )

    card_category = SelectField(
        "Card Category (Optional)",
        choices=[
            ("", "-- Select Category (Optional) --"),
            ("Credit Card", "Credit Card"),
            ("Debit Card", "Debit Card"),
            ("Prepaid / Travel", "Prepaid / Travel Card"),
            ("Corporate / Commercial", "Corporate / Commercial Card"),
        ],
        default="",
        validators=[Optional()],
    )

    billing_postal_code = StringField(
        "Billing Postal / PIN Code (Optional)",
        validators=[
            Optional(),
            Length(max=10, message="Postal code cannot exceed 10 characters."),
        ],
        render_kw={"placeholder": "e.g. 400001 or 560001"},
    )

    daily_limit = StringField(
        "Daily Spending Cap (Optional)",
        validators=[
            Optional(),
            Length(max=20, message="Spending cap cannot exceed 20 characters."),
        ],
        render_kw={"placeholder": "e.g. ₹50,000"},
    )

    international_tx = BooleanField("Enable International / Cross-Border Transactions (Optional)")

    demo_metadata = TextAreaField(
        "Encrypted Metadata (AES-256-GCM)",
        validators=[Length(max=500, message="Metadata cannot exceed 500 characters.")],
        render_kw={
            "placeholder": "Enter details (e.g. Bank Name, Branch Code, or Notes). This will be encrypted with AES-256-GCM.",
            "rows": 3,
        },
    )

    is_default = BooleanField("Set as default payment method")

    submit = SubmitField("Save Payment Method")


class RevealSecurityForm(FlaskForm):
    password = PasswordField(
        "Account Password",
        validators=[DataRequired(message="Account password is required.")],
        render_kw={
            "placeholder": "Enter your account password",
            "autocomplete": "current-password",
        },
    )

    security_key = PasswordField(
        "4-Digit Security Key",
        validators=[
            DataRequired(message="4-digit security key is required."),
            Length(min=4, max=4, message="Security key must be exactly 4 digits."),
            Regexp(r"^\d{4}$", message="Security key must contain exactly 4 numeric digits."),
        ],
        render_kw={
            "placeholder": "e.g. 1234",
            "maxlength": "4",
            "autocomplete": "off",
            "inputmode": "numeric",
            "pattern": "[0-9]{4}",
        },
    )

    submit = SubmitField("Verify & Decrypt Metadata")

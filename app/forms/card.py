# Form definition for creating and persisting simulated payment cards.
# Validates cardholder names, masked card numbers, and expiration dates while rejecting CVVs.

from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp


class DemoCardForm(FlaskForm):
    cardholder_name = StringField(
        "Simulated Cardholder Name",
        validators=[
            DataRequired(message="Cardholder name is required."),
            Length(min=2, max=100, message="Name must be between 2 and 100 characters."),
        ],
        render_kw={"placeholder": "e.g. Jane Doe (Simulated)"},
    )

    card_brand = SelectField(
        "Card Network Brand",
        choices=[
            ("Visa", "Visa"),
            ("Mastercard", "Mastercard"),
            ("American Express", "American Express"),
            ("Discover", "Discover"),
        ],
        default="Visa",
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
        },
    )

    exp_month = SelectField(
        "Expiration Month",
        coerce=int,
        choices=[(m, f"{m:02d}") for m in range(1, 13)],
        default=datetime.utcnow().month,
    )

    exp_year = SelectField(
        "Expiration Year",
        coerce=int,
        choices=[(y, str(y)) for y in range(datetime.utcnow().year, datetime.utcnow().year + 11)],
        default=datetime.utcnow().year + 2,
    )

    billing_details = TextAreaField(
        "Simulated Billing Details (Encrypted with AES-256-GCM)",
        validators=[Length(max=500, message="Billing details cannot exceed 500 characters.")],
        render_kw={
            "placeholder": "Enter fake demonstration billing address or notes to demonstrate AES-256-GCM encryption at rest.",
            "rows": 3,
        },
    )

    submit = SubmitField("Save Encrypted Demo Card")

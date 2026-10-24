# Financial transaction form definitions for wallet deposits and transfers.
# Validates monetary amounts and verifies recipient usernames before processing transactions.

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class DepositForm(FlaskForm):
    amount = StringField(
        "Deposit Amount (₹)",
        validators=[
            DataRequired(message="Please enter a deposit amount."),
            Length(max=20, message="Amount string is too long.")
        ]
    )
    description = StringField(
        "Note / Description (Optional)",
        validators=[Length(max=255, message="Description cannot exceed 255 characters.")],
        default="Deposit"
    )
    submit = SubmitField("Deposit Funds")


class TransferForm(FlaskForm):
    recipient = StringField(
        "Recipient Username or Email",
        validators=[
            DataRequired(message="Recipient username or email is required."),
            Length(max=120, message="Recipient identifier is too long.")
        ]
    )
    amount = StringField(
        "Transfer Amount (₹)",
        validators=[
            DataRequired(message="Please enter a transfer amount."),
            Length(max=20, message="Amount string is too long.")
        ]
    )
    note = StringField(
        "Note / Memo (Optional)",
        validators=[Length(max=255, message="Note cannot exceed 255 characters.")],
        default="P2P Transfer"
    )
    submit = SubmitField("Send Transfer")

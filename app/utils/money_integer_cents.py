# Exact monetary arithmetic utilities using integer cents to eliminate rounding errors.
# Converts decimal amount strings into integer cents and formats cents into currency strings.

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP


def parse_amount_to_cents(amount_input: str) -> tuple[bool, int, str]:
    if amount_input is None:
        return False, 0, "Amount is required."

    raw_str = str(amount_input).strip()
    if not raw_str:
        return False, 0, "Amount is required."

    try:
        dec = Decimal(raw_str)
    except (InvalidOperation, ValueError, TypeError):
        return False, 0, "Invalid amount format. Please enter a valid number (e.g., 25.50)."

    if dec <= Decimal("0"):
        return False, 0, "Amount must be strictly greater than zero (₹0.00)."

    if dec.as_tuple().exponent < -2:
        return False, 0, "Amount cannot have more than 2 decimal places."

    if dec > Decimal("10000000.00"):
        return False, 0, "Deposit cannot exceed ₹10,000,000.00 per transaction."

    cents_decimal = (dec * Decimal("100")).to_integral_value(rounding=ROUND_HALF_UP)
    cents = int(cents_decimal)

    return True, cents, ""


def format_cents(cents: int, currency: str = "INR") -> str:
    is_negative = cents < 0
    abs_cents = abs(cents)
    units = abs_cents // 100
    remainder = abs_cents % 100
    sign = "-" if is_negative else ""
    symbol = "₹"
    return f"{sign}{symbol}{units:,}.{remainder:02d}"

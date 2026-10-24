# Flask extensions registry for the Secure Digital Wallet application.
# Initializes and exports global SQLAlchemy database and CSRFProtect security extension instances.

from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()

csrf = CSRFProtect()

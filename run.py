# Entry point for the Secure Digital Wallet web application.
# Loads environment variables, creates the Flask app instance, and starts the development server.

import os
from dotenv import load_dotenv

load_dotenv()

from app import create_app

env_name = os.getenv("FLASK_ENV", "development")
app = create_app(env_name)

if __name__ == "__main__":
    print(f"[*] Starting VaultPay ({env_name} mode)...")
    print("[*] Server running at: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)

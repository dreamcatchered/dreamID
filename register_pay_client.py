import sqlite3
import secrets
import json
import os
from pathlib import Path
from datetime import datetime

DB_PATH = Path('/home/dream/projects/auth/dreamid.db')
client_id = "pay_admin"
# Use existing secret from DB, or take from environment, otherwise generate a new one.

conn = sqlite3.connect(DB_PATH)
existing = conn.execute("SELECT client_secret FROM clients WHERE client_id = ?", (client_id,)).fetchone()

if existing:
    client_secret = existing[0]
else:
    client_secret = os.environ.get("PAY_ADMIN_CLIENT_SECRET") or secrets.token_urlsafe(32)

name = "Pay Admin"
uris = [
    "https://pay.dreampartners.online/sso/callback",
    "http://pay.dreampartners.online/sso/callback",
    "http://localhost:5077/sso/callback"
]

if existing:
    conn.execute("UPDATE clients SET allowed_redirect_uris = ? WHERE client_id = ?",
                 (json.dumps(uris), client_id))
else:
    conn.execute("INSERT INTO clients (client_id, client_secret, name, allowed_redirect_uris, created_at) VALUES (?, ?, ?, ?, ?)",
                 (client_id, client_secret, name, json.dumps(uris), datetime.now().isoformat()))

conn.commit()
conn.close()

print(f"Updated pay_admin with URIs: {uris}")

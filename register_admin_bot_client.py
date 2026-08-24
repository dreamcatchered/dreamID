#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Register Admin Bot as OAuth client in dreamID database
Run this script on the server where auth service is running
"""
import sqlite3
import secrets
import json
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).parent / 'dreamid.db'

def generate_secret():
    """Generate a secure client secret"""
    return secrets.token_urlsafe(32)

def register_admin_bot_client():
    """Register Admin Bot in dreamID database"""
    
    client_id = "admin_bot"
    client_secret = generate_secret()
    name = "Admin Bot Panel"
    allowed_redirect_uris = [
        "https://manage.dreampartners.online/sso/callback",
        "http://localhost:5001/sso/callback"
    ]
    
    print("=" * 50)
    print("Registering Admin Bot in dreamID SSO")
    print("=" * 50)
    print()
    
    if not DB_PATH.exists():
        print(f"❌ Database not found: {DB_PATH}")
        print("Make sure you run this script from the auth project directory")
        return None
    
    conn = sqlite3.connect(str(DB_PATH))
    
    try:
        # Check if already exists
        existing = conn.execute(
            'SELECT client_id FROM clients WHERE client_id = ?', 
            (client_id,)
        ).fetchone()
        
        if existing:
            print(f"⚠️  Client '{client_id}' already exists!")
            print("Updating client secret...")
            
            conn.execute(
                '''UPDATE clients 
                   SET client_secret = ?, 
                       name = ?, 
                       allowed_redirect_uris = ?
                   WHERE client_id = ?''',
                (client_secret, name, json.dumps(allowed_redirect_uris), client_id)
            )
            conn.commit()
            print("✅ Client updated successfully!")
        else:
            # Insert new client
            conn.execute(
                '''INSERT INTO clients 
                   (client_id, client_secret, name, allowed_redirect_uris, created_at) 
                   VALUES (?, ?, ?, ?, ?)''',
                (client_id, client_secret, name, json.dumps(allowed_redirect_uris), 
                 datetime.utcnow().isoformat())
            )
            conn.commit()
            print("✅ Client registered successfully!")
        
        conn.close()
        
        print()
        print("Client details:")
        print("-" * 40)
        print(f"Client ID: {client_id}")
        print(f"Client Secret: {client_secret}")
        print(f"Redirect URIs: {allowed_redirect_uris}")
        print("-" * 40)
        print()
        print("Add these to admin_bot/.env file:")
        print()
        print(f"DREAMID_CLIENT_ID={client_id}")
        print(f"DREAMID_CLIENT_SECRET={client_secret}")
        print(f"DREAMID_AUTH_URL=https://auth.dreampartners.online")
        print()
        
        return {
            "service": name,
            "domain": "manage.dreampartners.online",
            "client_id": client_id,
            "client_secret": client_secret,
            "status": "success"
        }
        
    except Exception as e:
        conn.close()
        print(f"❌ Error: {e}")
        return None

if __name__ == '__main__':
    result = register_admin_bot_client()
    
    if result:
        # Update registration_results.json
        results_file = Path(__file__).parent / 'registration_results.json'
        
        if results_file.exists():
            with open(results_file, 'r', encoding='utf-8') as f:
                results = json.load(f)
        else:
            results = []
        
        # Check if admin_bot already in results
        found = False
        for i, r in enumerate(results):
            if r.get('client_id') == 'admin_bot':
                results[i] = result
                found = True
                break
        
        if not found:
            results.append(result)
        
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"📝 Updated {results_file}")

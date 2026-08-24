#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт для регистрации/обновления cloud клиента в dreamID
"""
import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).parent / 'dreamid.db'

# Секрет берётся из переменной окружения; при первом запуске можно задать CLOUD_CLIENT_SECRET
CLOUD_CLIENT = {
    'client_id': 'dream_cloud',
    'client_secret': os.environ.get('CLOUD_CLIENT_SECRET', ''),
    'name': 'Dream Cloud Storage',
    'allowed_redirect_uris': [
        'https://cloud.dreampartners.online/sso/callback',
        'http://localhost:5033/sso/callback'
    ]
}


def show_all_clients():
    """Показать всех зарегистрированных клиентов"""
    if not DB_PATH.exists():
        print(f"❌ База данных не найдена: {DB_PATH}")
        return
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.execute(
        'SELECT client_id, name, allowed_redirect_uris, created_at FROM clients ORDER BY created_at'
    )
    clients = cursor.fetchall()
    conn.close()
    
    print("=" * 70)
    print("Зарегистрированные OAuth клиенты в dreamID")
    print("=" * 70)
    
    if not clients:
        print("(нет клиентов)")
        return
    
    for client_id, name, uris_json, created_at in clients:
        print(f"\n📱 {name or client_id}")
        print(f"   client_id: {client_id}")
        try:
            uris = json.loads(uris_json) if uris_json else []
            print(f"   redirect_uris:")
            for uri in uris:
                print(f"     - {uri}")
        except:
            print(f"   redirect_uris: {uris_json}")
        print(f"   created: {created_at or 'N/A'}")
    
    print("\n" + "=" * 70)


def register_or_update_cloud():
    """Зарегистрировать или обновить cloud клиента"""
    if not DB_PATH.exists():
        print(f"❌ База данных не найдена: {DB_PATH}")
        return False
    
    conn = sqlite3.connect(str(DB_PATH))
    
    # Проверить существует ли клиент
    cursor = conn.execute(
        'SELECT client_id, allowed_redirect_uris FROM clients WHERE client_id = ?',
        (CLOUD_CLIENT['client_id'],)
    )
    row = cursor.fetchone()
    
    uris_json = json.dumps(CLOUD_CLIENT['allowed_redirect_uris'])
    
    if row:
        # Обновить существующего клиента
        print(f"🔄 Клиент {CLOUD_CLIENT['client_id']} найден, обновляю...")
        
        conn.execute(
            '''UPDATE clients 
               SET client_secret = ?, 
                   name = ?, 
                   allowed_redirect_uris = ?
               WHERE client_id = ?''',
            (CLOUD_CLIENT['client_secret'], 
             CLOUD_CLIENT['name'], 
             uris_json, 
             CLOUD_CLIENT['client_id'])
        )
    else:
        # Создать нового клиента
        print(f"➕ Создаю нового клиента {CLOUD_CLIENT['client_id']}...")
        
        conn.execute(
            '''INSERT INTO clients 
               (client_id, client_secret, name, allowed_redirect_uris, created_at) 
               VALUES (?, ?, ?, ?, ?)''',
            (CLOUD_CLIENT['client_id'], 
             CLOUD_CLIENT['client_secret'], 
             CLOUD_CLIENT['name'], 
             uris_json,
             datetime.utcnow().isoformat())
        )
    
    conn.commit()
    conn.close()
    
    print(f"\n✅ Клиент {CLOUD_CLIENT['client_id']} зарегистрирован!")
    print(f"\n   Client ID: {CLOUD_CLIENT['client_id']}")
    print(f"   Client Secret: {CLOUD_CLIENT['client_secret']}")
    print(f"   Redirect URIs:")
    for uri in CLOUD_CLIENT['allowed_redirect_uris']:
        print(f"     - {uri}")
    
    return True


if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("Dream Cloud - Регистрация SSO клиента")
    print("=" * 70)
    
    print("\n1. Регистрация/обновление cloud клиента:\n")
    register_or_update_cloud()
    
    print("\n\n2. Все клиенты после обновления:\n")
    show_all_clients()

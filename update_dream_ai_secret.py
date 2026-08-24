#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт для обновления client_secret для dream_ai
"""

import sqlite3
import os
import re
from pathlib import Path

# Пути
AUTH_DB = Path(__file__).parent / 'dreamid.db'
GPT_APP = Path(__file__).parent.parent / 'gpt' / 'web' / 'app.py'

def get_current_secret():
    """Получает текущий client_secret для dream_ai из базы"""
    if not AUTH_DB.exists():
        print(f"База данных не найдена: {AUTH_DB}")
        return None
    
    conn = sqlite3.connect(str(AUTH_DB))
    try:
        cursor = conn.execute(
            'SELECT client_secret FROM clients WHERE client_id = ?',
            ('dream_ai',)
        )
        row = cursor.fetchone()
        if row:
            return row[0]
        else:
            print("dream_ai не найден в базе данных")
            return None
    finally:
        conn.close()

def update_gpt_app(secret):
    """Обновляет client_secret в gpt/web/app.py"""
    if not GPT_APP.exists():
        print(f"Файл не найден: {GPT_APP}")
        return False
    
    with open(GPT_APP, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Ищем и заменяем SSO_CLIENT_SECRET
    pattern = r'SSO_CLIENT_SECRET\s*=\s*["\']([^"\']+)["\']'
    replacement = f'SSO_CLIENT_SECRET = "{secret}"'
    
    if re.search(pattern, content):
        content = re.sub(pattern, replacement, content)
        with open(GPT_APP, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"✅ Обновлен client_secret в {GPT_APP}")
        return True
    else:
        print(f"⚠️  SSO_CLIENT_SECRET не найден в {GPT_APP}")
        return False

def main():
    print("=" * 80)
    print("Обновление client_secret для dream_ai")
    print("=" * 80)
    print()
    
    # Получаем актуальный secret из базы
    secret = get_current_secret()
    if not secret:
        print("❌ Не удалось получить client_secret из базы данных")
        return
    
    print(f"📋 Текущий client_secret для dream_ai: {secret[:20]}...")
    print()
    
    # Обновляем в gpt/web/app.py
    if update_gpt_app(secret):
        print()
        print("✅ Готово! client_secret обновлен в gpt/web/app.py")
    else:
        print()
        print("❌ Не удалось обновить client_secret")

if __name__ == "__main__":
    main()


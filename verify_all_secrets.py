#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт для проверки актуальности всех SSO client_secret
"""

import sqlite3
import json
import re
from pathlib import Path

# Пути
AUTH_DB = Path(__file__).parent / 'dreamid.db'
REGISTRATION_RESULTS = Path(__file__).parent / 'registration_results.json'

# Проекты с SSO
PROJECTS = {
    'dream_ai': {
        'file': Path(__file__).parent.parent / 'gpt' / 'web' / 'app.py',
        'pattern': r'SSO_CLIENT_SECRET\s*=\s*["\']([^"\']+)["\']'
    },
    'dream_mp3': {
        'file': Path(__file__).parent.parent / 'mp3' / 'prod' / 'app.py',
        'pattern': r'SSO_CLIENT_SECRET\s*=\s*["\']([^"\']+)["\']'
    },
    'dream_app': {
        'file': Path(__file__).parent.parent / 'dp' / 'webapp' / 'config.py',
        'pattern': r'SSO_CLIENT_SECRET\s*=\s*["\']([^"\']+)["\']'
    },
    'dream_cpa': {
        'file': Path(__file__).parent.parent / 'dp' / 'cpa' / 'app.py',
        'pattern': r'SSO_CLIENT_SECRET\s*=\s*["\']([^"\']+)["\']'
    },
    'dream_download': {
        'file': Path(__file__).parent.parent / 'down' / 'api.py',
        'pattern': r'SSO_CLIENT_SECRET\s*=\s*["\']([^"\']+)["\']'
    }
}

def get_secret_from_db(client_id):
    """Получает client_secret из базы данных"""
    if not AUTH_DB.exists():
        return None
    
    conn = sqlite3.connect(str(AUTH_DB))
    try:
        cursor = conn.execute(
            'SELECT client_secret FROM clients WHERE client_id = ?',
            (client_id,)
        )
        row = cursor.fetchone()
        return row[0] if row else None
    finally:
        conn.close()

def get_secret_from_file(file_path, pattern):
    """Получает client_secret из файла"""
    if not file_path.exists():
        return None
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    match = re.search(pattern, content)
    return match.group(1) if match else None

def get_secret_from_registration(client_id):
    """Получает client_secret из registration_results.json"""
    if not REGISTRATION_RESULTS.exists():
        return None
    
    with open(REGISTRATION_RESULTS, 'r', encoding='utf-8') as f:
        results = json.load(f)
    
    for result in results:
        if result.get('client_id') == client_id and result.get('status') == 'success':
            return result.get('client_secret')
    return None

def main():
    print("=" * 80)
    print("Проверка актуальности SSO client_secret")
    print("=" * 80)
    print()
    
    all_ok = True
    
    for client_id, project in PROJECTS.items():
        print(f"📋 Проверка {client_id}:")
        
        # Получаем secret из базы данных
        db_secret = get_secret_from_db(client_id)
        
        # Получаем secret из файла проекта
        file_secret = get_secret_from_file(project['file'], project['pattern'])
        
        # Получаем secret из registration_results (для справки)
        reg_secret = get_secret_from_registration(client_id)
        
        if not db_secret:
            print(f"   ⚠️  Не найден в базе данных")
            all_ok = False
            continue
        
        if not file_secret:
            print(f"   ⚠️  Не найден в файле: {project['file']}")
            all_ok = False
            continue
        
        if db_secret == file_secret:
            print(f"   ✅ Актуален: {file_secret[:20]}...")
        else:
            print(f"   ❌ НЕ АКТУАЛЕН!")
            print(f"      В базе:    {db_secret[:20]}...")
            print(f"      В файле:   {file_secret[:20]}...")
            if reg_secret:
                print(f"      В регистрации: {reg_secret[:20]}...")
            all_ok = False
        
        print()
    
    print("=" * 80)
    if all_ok:
        print("✅ Все client_secret актуальны!")
    else:
        print("❌ Обнаружены несоответствия!")
    print("=" * 80)

if __name__ == "__main__":
    main()


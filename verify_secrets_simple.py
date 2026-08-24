#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Простая проверка соответствия client_secret в файлах с registration_results.json
"""

import json
import re
from pathlib import Path

REGISTRATION_RESULTS = Path(__file__).parent / 'registration_results.json'

PROJECTS = {
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
    print("Проверка соответствия client_secret в файлах с registration_results.json")
    print("=" * 80)
    print()
    
    all_ok = True
    
    for client_id, project in PROJECTS.items():
        print(f"📋 {client_id}:")
        
        file_secret = get_secret_from_file(project['file'], project['pattern'])
        reg_secret = get_secret_from_registration(client_id)
        
        if not file_secret:
            print(f"   ❌ Не найден в файле: {project['file']}")
            all_ok = False
        elif not reg_secret:
            print(f"   ⚠️  Не найден в registration_results.json")
            print(f"      В файле: {file_secret[:30]}...")
        elif file_secret == reg_secret:
            print(f"   ✅ Соответствует: {file_secret[:30]}...")
        else:
            print(f"   ❌ НЕ СООТВЕТСТВУЕТ!")
            print(f"      В файле:   {file_secret[:30]}...")
            print(f"      В регистрации: {reg_secret[:30]}...")
            all_ok = False
        
        print()
    
    print("=" * 80)
    if all_ok:
        print("✅ Все client_secret соответствуют registration_results.json!")
    else:
        print("❌ Обнаружены несоответствия!")
    print("=" * 80)

if __name__ == "__main__":
    main()


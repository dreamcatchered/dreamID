#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sqlite3
from pathlib import Path

db_path = Path(__file__).parent / 'dreamid.db'

if not db_path.exists():
    print(f"База данных не найдена: {db_path}")
    exit(1)

conn = sqlite3.connect(str(db_path))
cursor = conn.execute('SELECT name FROM sqlite_master WHERE type="table"')
tables = cursor.fetchall()
print('Таблицы в БД:')
for t in tables:
    print(f'  - {t[0]}')

print()
print('Клиенты в таблице clients:')
cursor = conn.execute('SELECT client_id, name, created_at FROM clients')
clients = cursor.fetchall()
if clients:
    for client in clients:
        print(f'  - {client[0]}: {client[1]} (создан: {client[2]})')
else:
    print('  (нет клиентов)')

conn.close()


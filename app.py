from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response, has_request_context
from flask.sessions import SecureCookieSessionInterface
from flask_cors import CORS
import json
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets
import time
import requests
from datetime import datetime, timedelta
import os
import stat
from dotenv import load_dotenv
from functools import wraps

# Определяем базовую директорию приложения
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Загружаем переменные окружения из .env файла
# Пробуем загрузить из текущей директории и из BASE_DIR
env_path = os.path.join(BASE_DIR, '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    # Если .env не найден, пробуем загрузить из текущей директории
    load_dotenv()
    print(f"Warning: .env file not found at {env_path}, using default environment")

app = Flask(__name__)

# Обеспечиваем постоянный SECRET_KEY для persistent sessions
def ensure_secret_key():
    """Проверяет и создает постоянный SECRET_KEY в .env файле"""
    env_file = os.path.join(BASE_DIR, '.env')
    secret_key = os.environ.get('SECRET_KEY')
    
    if not secret_key:
        # Пытаемся прочитать из .env файла
        if os.path.exists(env_file):
            with open(env_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('SECRET_KEY='):
                        secret_key = line.split('=', 1)[1].strip().strip('"').strip("'")
                        break
        
        # Если ключа нет, создаем новый и сохраняем в .env
        if not secret_key:
            secret_key = secrets.token_hex(32)
            # Сохраняем в .env
            try:
                # Читаем существующий .env если есть
                existing_content = ''
                if os.path.exists(env_file):
                    with open(env_file, 'r', encoding='utf-8') as f:
                        existing_content = f.read()
                
                # Добавляем SECRET_KEY если его нет
                if 'SECRET_KEY=' not in existing_content:
                    with open(env_file, 'a', encoding='utf-8') as f:
                        if existing_content and not existing_content.endswith('\n'):
                            f.write('\n')
                        f.write(f'SECRET_KEY={secret_key}\n')
                    print(f"Created SECRET_KEY in {env_file}")
                else:
                    # Обновляем существующий
                    lines = existing_content.split('\n')
                    new_lines = []
                    for line in lines:
                        if line.startswith('SECRET_KEY='):
                            new_lines.append(f'SECRET_KEY={secret_key}')
                        else:
                            new_lines.append(line)
                    with open(env_file, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(new_lines))
                    print(f"Updated SECRET_KEY in {env_file}")
            except Exception as e:
                print(f"Warning: Could not save SECRET_KEY to .env file: {e}")
                print(f"Please set SECRET_KEY={secret_key} in your .env file manually")
    
    return secret_key

app.secret_key = ensure_secret_key()

# Настройка сессий для работы между разными доменами
# В продакшене сессии работают только на своем домене (auth.dreampartners.online)
# Это нормально - каждый домен имеет свою сессию

# Определяем, работаем ли мы в режиме разработки
is_production = os.environ.get('FLASK_ENV') == 'production'

if is_production:
    # Для продакшена используем Lax (HTTPS)
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = True  # True для HTTPS
else:
    # Для разработки с поддоменами (auth.dev, site.dev) используем Lax
    # Это работает, потому что auth.dev и site.dev - разные домены
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = False  # False для HTTP на dev доменах

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_DOMAIN'] = None  # None = только текущий домен
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Настройка CORS для SSO
CORS(app, resources={
    r"/api/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]},
    r"/sso": {"origins": "*", "methods": ["GET", "OPTIONS"]},
    r"/login": {"origins": "*", "methods": ["GET", "OPTIONS"]}
}, supports_credentials=True, expose_headers=['Location'])

# Конфигурация
SMS_API_URL = "https://sms.dreampartners.online/api/sms"
SMS_API_KEY = os.environ.get('SMS_API_KEY', '')  # Получите из бота @dream_smsbot
AUTH_BASE_URL = os.environ.get('AUTH_BASE_URL', 'https://auth.dreampartners.online')
CODE_EXPIRY_MINUTES = 10
SSO_CODE_EXPIRY_MINUTES = 5
QUICK_LOGIN_TOKEN_EXPIRY_MINUTES = 5

# Логирование для отладки (только при запуске)
if not SMS_API_KEY:
    print(f"WARNING: SMS_API_KEY not set! SMS functionality will not work.")
    print(f"BASE_DIR: {BASE_DIR}")
    print(f"env_path: {env_path}")
    print(f"Environment variables: SMS_API_KEY={'SET' if os.environ.get('SMS_API_KEY') else 'NOT SET'}")

# Получаем абсолютный путь к базе данных (BASE_DIR уже определен выше)
DB_PATH = os.path.join(BASE_DIR, 'dreamid.db')

# Кастомный SQLite Session Interface для persistent sessions
class SQLiteSessionInterface(SecureCookieSessionInterface):
    """Кастомный интерфейс сессий, хранящий данные в SQLite базе данных"""
    
    serializer = json
    
    def open_session(self, app, request):
        """Открыть сессию из базы данных"""
        cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
        sid = request.cookies.get(cookie_name)
        if not sid:
            # Создаем новую сессию
            return self.session_class()
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            # Очищаем истекшие сессии
            cursor.execute('DELETE FROM sessions WHERE expiry < datetime("now")')
            # Получаем сессию
            cursor.execute(
                'SELECT data, expiry FROM sessions WHERE session_id = ?',
                (sid,)
            )
            row = cursor.fetchone()
            conn.commit()
            conn.close()
            
            if row and row[1]:
                expiry = datetime.fromisoformat(row[1])
                if expiry > datetime.now():
                    # Сессия валидна
                    try:
                        data = self.serializer.loads(row[0])
                        session = self.session_class(data)
                        session.permanent = True
                        return session
                    except:
                        pass
            
            # Сессия не найдена или истекла
            return self.session_class()
        except Exception as e:
            print(f"Error opening session: {e}")
            return self.session_class()
    
    def save_session(self, app, session_obj, response):
        """Сохранить сессию в базу данных"""
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        
        # Получаем request из контекста Flask
        if not has_request_context():
            return
        
        # Если сессия пустая, удаляем её из БД
        if not session_obj:
            return
        
        if len(session_obj) == 0:
            if session_obj.modified:
                # Удаляем из БД
                try:
                    cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
                    sid = request.cookies.get(cookie_name)
                    if sid:
                        conn = sqlite3.connect(DB_PATH)
                        conn.execute('DELETE FROM sessions WHERE session_id = ?', (sid,))
                        conn.commit()
                        conn.close()
                except Exception as e:
                    print(f"Error deleting session: {e}")
                cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
                response.delete_cookie(cookie_name, domain=domain, path=path)
            return
        
        # Получаем или создаем session ID
        cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
        sid = request.cookies.get(cookie_name)
        if not sid:
            sid = secrets.token_urlsafe(32)
        
        # Вычисляем время истечения
        if session_obj.permanent:
            lifetime = app.permanent_session_lifetime
        else:
            lifetime = timedelta(days=1)
        
        expiry = datetime.now() + lifetime
        
        # Сериализуем данные сессии
        try:
            data = self.serializer.dumps(dict(session_obj))
            
            # Сохраняем в БД
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                '''INSERT OR REPLACE INTO sessions (session_id, data, expiry)
                   VALUES (?, ?, ?)''',
                (sid, data, expiry.isoformat())
            )
            conn.commit()
            conn.close()
            
            # Устанавливаем cookie
            response.set_cookie(
                cookie_name,
                sid,
                expires=expiry,
                httponly=app.config.get('SESSION_COOKIE_HTTPONLY', True),
                domain=domain,
                path=path,
                secure=app.config.get('SESSION_COOKIE_SECURE', False),
                samesite=app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')
            )
        except Exception as e:
            print(f"Error saving session: {e}")

# Функция для проверки и исправления прав доступа к БД
def ensure_db_permissions():
    """Проверяет и исправляет права доступа к базе данных и директории"""
    try:
        # Проверяем права на директорию
        if not os.access(BASE_DIR, os.W_OK):
            print(f"ERROR: No write permission for directory: {BASE_DIR}")
            return False
        
        # Если база данных существует, проверяем права на неё
        if os.path.exists(DB_PATH):
            if not os.access(DB_PATH, os.W_OK):
                print(f"ERROR: Database file exists but is read-only: {DB_PATH}")
                print(f"Fix with: chmod 664 {DB_PATH} && chown dream:dream {DB_PATH}")
                return False
        else:
            # Если базы нет, проверяем, можем ли создать файл
            try:
                test_file = DB_PATH + '.test'
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
            except Exception as e:
                print(f"ERROR: Cannot create database file in {BASE_DIR}: {e}")
                return False
        
        return True
    except Exception as e:
        print(f"ERROR checking database permissions: {e}")
        return False

# Инициализация БД
def init_db():
    # Проверяем права перед подключением
    if not ensure_db_permissions():
        raise PermissionError(f"Cannot access database at {DB_PATH}. Check file permissions.")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Пользователи (phone может быть NULL)
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  phone TEXT,
                  avatar TEXT,
                  first_name TEXT,
                  last_name TEXT,
                  email TEXT,
                  country TEXT,
                  city TEXT,
                  telegram_username TEXT,
                  telegram_id INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # SSO коды (временные коды для обмена на токен)
    c.execute('''CREATE TABLE IF NOT EXISTS sso_codes
                 (code TEXT PRIMARY KEY,
                  user_id INTEGER NOT NULL,
                  redirect_uri TEXT NOT NULL,
                  client_id TEXT,
                  state TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  expires_at TIMESTAMP NOT NULL,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # SSO токены (для доступа к API)
    c.execute('''CREATE TABLE IF NOT EXISTS sso_tokens
                 (token TEXT PRIMARY KEY,
                  user_id INTEGER NOT NULL,
                  client_id TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  expires_at TIMESTAMP NOT NULL,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Временные коды подтверждения телефона
    c.execute('''CREATE TABLE IF NOT EXISTS phone_verification
                 (phone TEXT PRIMARY KEY,
                  code TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  expires_at TIMESTAMP NOT NULL)''')
    
    # Зарегистрированные клиенты (OAuth 2.0 clients)
    c.execute('''CREATE TABLE IF NOT EXISTS clients
                 (client_id TEXT PRIMARY KEY,
                  client_secret TEXT NOT NULL,
                  name TEXT,
                  allowed_redirect_uris TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Токены быстрого входа через Telegram
    c.execute('''CREATE TABLE IF NOT EXISTS quick_login_tokens
                 (token TEXT PRIMARY KEY,
                  redirect_uri TEXT,
                  client_id TEXT,
                  state TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  expires_at TIMESTAMP NOT NULL)''')
    
    # Сессии пользователей (для persistent sessions)
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (session_id TEXT PRIMARY KEY,
                  data TEXT NOT NULL,
                  expiry TIMESTAMP NOT NULL)''')
    
    # Создаем индекс для быстрой очистки истекших сессий
    c.execute('''CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expiry)''')
    
    conn.commit()
    conn.close()

# Функция исправления схемы БД (миграция)
def fix_db_schema():
    """Миграция для allow NULL в phone"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        # Проверяем, позволяет ли users.phone NULL
        # (Проверка упрощена - просто пробуем вставить NULL)
        # Но проще проверить PRAGMA table_info
        c.execute("PRAGMA table_info(users)")
        columns = c.fetchall()
        phone_col = next((col for col in columns if col[1] == 'phone'), None)
        
        # phone_col[3] is 'notnull' (1 if NOT NULL, 0 if NULL allowed)
        columns_list = [col[1] for col in columns]
        needs_migration = False
        new_fields = ['first_name', 'last_name', 'email', 'country', 'city', 'telegram_username', 'telegram_id']
        missing_fields = [field for field in new_fields if field not in columns_list]
        
        if phone_col and phone_col[3] == 1:
            needs_migration = True
            print("Migrating users table to allow NULL phone and add new fields...")
        elif 'avatar' not in columns_list or missing_fields:
            needs_migration = True
            print(f"Migrating users table to add missing fields: {missing_fields}...")
        
        if needs_migration:
            c.execute("ALTER TABLE users RENAME TO users_old")
            c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  phone TEXT,
                  avatar TEXT,
                  first_name TEXT,
                  last_name TEXT,
                  email TEXT,
                  country TEXT,
                  city TEXT,
                  telegram_username TEXT,
                  telegram_id INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
            
            # Копируем данные (только существующие колонки)
            existing_cols = [col for col in ['id', 'username', 'password_hash', 'phone', 'avatar', 'created_at'] if col in columns_list]
            cols_str = ', '.join(existing_cols)
            c.execute(f"INSERT INTO users ({cols_str}) SELECT {cols_str} FROM users_old")
            c.execute("DROP TABLE users_old")
            conn.commit()
            print("Migration successful.")
        else:
            # Добавляем только недостающие поля
            for field in missing_fields:
                try:
                    field_type = 'INTEGER' if field == 'telegram_id' else 'TEXT'
                    c.execute(f'ALTER TABLE users ADD COLUMN {field} {field_type}')
                    print(f"Added {field} column to users table.")
                except Exception as e:
                    print(f"Error adding {field}: {e}")
            if missing_fields:
                conn.commit()
    except Exception as e:
        print(f"Schema fix error: {e}")
        conn.rollback()
    finally:
        conn.close()

# Проверяем права доступа перед инициализацией
if not ensure_db_permissions():
    print("WARNING: Database permissions check failed. The application may not work correctly.")
    print(f"Please run: sudo chmod 664 {DB_PATH} && sudo chown dream:dream {DB_PATH}")
    print(f"Or if DB doesn't exist: sudo chmod 775 {BASE_DIR} && sudo chown dream:dream {BASE_DIR}")

init_db()
fix_db_schema() # Run schema fix

# Миграция: добавляем поле state если его нет
def migrate_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        # Проверяем, есть ли поле state
        c.execute("PRAGMA table_info(sso_codes)")
        columns = [row[1] for row in c.fetchall()]
        if 'state' not in columns:
            c.execute('ALTER TABLE sso_codes ADD COLUMN state TEXT')
            conn.commit()
            print("Database migrated: added state column")
    except Exception as e:
        print(f"Migration error (may be OK if column exists): {e}")
    conn.close()

migrate_db()

# Миграция: добавляем таблицу clients если её нет
def migrate_clients():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='clients'")
        if not c.fetchone():
            c.execute('''CREATE TABLE clients
                         (client_id TEXT PRIMARY KEY,
                          client_secret TEXT NOT NULL,
                          name TEXT,
                          allowed_redirect_uris TEXT NOT NULL,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
            conn.commit()
            print("Database migrated: added clients table")
    except Exception as e:
        print(f"Migration error (clients): {e}")
    conn.close()

migrate_clients()

# Миграция: добавляем таблицу quick_login_tokens если её нет
def migrate_quick_login_tokens():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='quick_login_tokens'")
        if not c.fetchone():
            c.execute('''CREATE TABLE quick_login_tokens
                         (token TEXT PRIMARY KEY,
                          redirect_uri TEXT,
                          client_id TEXT,
                          state TEXT,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                          expires_at TIMESTAMP NOT NULL)''')
            conn.commit()
            print("Database migrated: added quick_login_tokens table")
    except Exception as e:
        print(f"Migration error (quick_login_tokens): {e}")
    conn.close()

migrate_quick_login_tokens()

# Миграция: добавляем таблицу sessions если её нет
def migrate_sessions():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'")
        if not c.fetchone():
            c.execute('''CREATE TABLE sessions
                         (session_id TEXT PRIMARY KEY,
                          data TEXT NOT NULL,
                          expiry TIMESTAMP NOT NULL)''')
            c.execute('''CREATE INDEX idx_sessions_expiry ON sessions(expiry)''')
            conn.commit()
            print("Database migrated: added sessions table")
    except Exception as e:
        print(f"Migration error (sessions): {e}")
    conn.close()

migrate_sessions()

# Устанавливаем кастомный SQLite session interface для persistent sessions
app.session_interface = SQLiteSessionInterface()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    # Исправление для Python 3.12+ (убирает DeprecationWarning)
    def adapt_datetime_iso(val):
        return val.isoformat()
    
    sqlite3.register_adapter(datetime, adapt_datetime_iso)
    
    return conn

# Функции для работы с клиентами
def get_client(client_id):
    """Получить информацию о клиенте"""
    conn = get_db()
    client = conn.execute(
        'SELECT * FROM clients WHERE client_id = ?', (client_id,)
    ).fetchone()
    conn.close()
    return client

def verify_client_secret(client_id, client_secret):
    """Проверить client_secret"""
    client = get_client(client_id)
    if not client:
        return False
    return client['client_secret'] == client_secret

def is_redirect_uri_allowed(client_id, redirect_uri):
    """Проверить, разрешен ли redirect_uri для данного client_id"""
    client = get_client(client_id)
    if not client:
        return False
    
    import json
    try:
        allowed_uris = json.loads(client['allowed_redirect_uris'])
        # Проверяем точное совпадение или домен
        for allowed_uri in allowed_uris:
            if redirect_uri == allowed_uri:
                return True
            # Разрешаем поддомены (например, https://app.example.com если разрешен https://example.com)
            if redirect_uri.startswith(allowed_uri.rstrip('/') + '/'):
                return True
        return False
    except:
        return False

def register_client(client_id, client_secret, name, allowed_redirect_uris):
    """Зарегистрировать нового клиента"""
    conn = sqlite3.connect(DB_PATH)
    import json
    
    try:
        # Проверяем, не существует ли уже
        existing = conn.execute(
            'SELECT client_id FROM clients WHERE client_id = ?', (client_id,)
        ).fetchone()
        
        if existing:
            conn.close()
            return False, "Client ID already exists" # Internal, but kept English for logs/admin
        
        # Сохраняем как JSON массив
        uris_json = json.dumps(allowed_redirect_uris if isinstance(allowed_redirect_uris, list) else [allowed_redirect_uris])
        
        conn.execute(
            'INSERT INTO clients (client_id, client_secret, name, allowed_redirect_uris) VALUES (?, ?, ?, ?)',
            (client_id, client_secret, name, uris_json)
        )
        conn.commit()
        conn.close()
        return True, "Client registered successfully"
    except Exception as e:
        conn.close()
        return False, str(e)

# SMS функции
def send_sms_code(phone, code):
    """Отправка кода через SMS API"""
    if not SMS_API_KEY:
        print("WARNING: SMS_API_KEY not set. SMS sending disabled.")
        return False, "SMS API не настроен"
    
    try:
        response = requests.post(
            f"{SMS_API_URL}/send",
            json={
                "api_key": SMS_API_KEY,
                "phone": phone,
                "code": code
            },
            timeout=10
        )
        result = response.json()
        success = result.get('success', False)
        error_msg = result.get('error', '')
        
        # Проверяем специальные ошибки
        if not success:
            if 'not registered' in error_msg.lower() or 'не зарегистрирован' in error_msg.lower() or 'not found' in error_msg.lower():
                return False, "not_registered"
            return False, error_msg or "Ошибка отправки SMS"
        
        return True, None
    except Exception as e:
        print(f"SMS send error: {e}")
        return False, "Ошибка соединения с SMS сервисом"

def verify_sms_code(phone, code, api_key=None):
    """Проверка кода через SMS API
    
    Returns:
        tuple: (success: bool, error_message: str or None, user_data: dict or None)
    """
    try:
        json_data = {
            "phone": phone,
            "code": code
        }
        if api_key:
            json_data["api_key"] = api_key
        
        response = requests.post(
            f"{SMS_API_URL}/verify",
            json=json_data,
            timeout=10
        )
        result = response.json()
        success = result.get('success', False)
        error_msg = result.get('error', '')
        user_data = result.get('user_data')
        
        if not success:
            # Возвращаем кортеж (success, error_message, user_data)
            if 'not registered' in error_msg.lower() or 'не зарегистрирован' in error_msg.lower():
                return False, "not_registered", None
            return False, error_msg or "Неверный или истекший код", None
        
        return True, None, user_data
    except Exception as e:
        print(f"SMS verify error: {e}")
        return False, "Ошибка соединения с SMS сервисом", None

# API для проверки авторизации (для SSO)
@app.route('/api/sso/check', methods=['GET'])
def sso_check():
    """Проверяет, авторизован ли пользователь (для SSO)"""
    user_id = session.get('user_id')
    if user_id:
        conn = get_db()
        user = conn.execute(
            'SELECT id, username FROM users WHERE id = ?', (user_id,)
        ).fetchone()
        conn.close()
        if user:
            response = jsonify({
                "authenticated": True,
                "user_id": user['id'],
                "username": user['username']
            })
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response
    
    response = jsonify({"authenticated": False})
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

# OAuth 2.0 стандартный endpoint /authorize
@app.route('/authorize')
@app.route('/oauth/authorize')
def oauth_authorize():
    """Стандартный OAuth 2.0 Authorization Endpoint"""
    # Перенаправляем на /sso с теми же параметрами
    return sso_auth()

# Главная страница - SSO авторизация (OAuth 2.0 flow)
@app.route('/sso')
def sso_auth():
    redirect_uri = request.args.get('redirect_uri')
    client_id = request.args.get('client_id', '')
    state = request.args.get('state', '')  # Для безопасности и возврата на клиента
    
    if not redirect_uri:
        return jsonify({"error": "redirect_uri is required"}), 400
    
    # Проверяем, что клиент зарегистрирован и redirect_uri разрешен
    if client_id:
        if not get_client(client_id):
            return jsonify({"error": "Неверный client_id"}), 400
        
        if not is_redirect_uri_allowed(client_id, redirect_uri):
            return jsonify({"error": "redirect_uri не разрешен для этого клиента"}), 400
    
    # Проверяем авторизацию через сессию (работает на своем домене: auth.test)
    # С поддоменами (auth.test и site.test) cookies работают правильно с SameSite=Lax
    
    user_id = session.get('user_id')
    username = session.get('username')
    
    # Логируем для отладки
    print(f"SSO request from {request.headers.get('Referer', 'direct')}")
    print(f"SSO request: user_id={user_id}, username={username}")
    print(f"Session keys: {list(session.keys())}")
    
    # Если пользователь уже авторизован на этом домене, сразу выдаем код
    if user_id:
        print(f"User {username} (ID: {user_id}) is authenticated, redirecting to client")
        try:
            return redirect_to_client(redirect_uri, client_id, user_id, state)
        except Exception as e:
            print(f"Error in redirect_to_client: {e}")
            import traceback
            traceback.print_exc()
            # Если ошибка, показываем форму входа с параметрами в URL
            pass
    else:
        print("User not authenticated, showing login form")
    
    # Пользователь не авторизован - показываем форму входа
    # Сохраняем параметры в URL для надежности (работает между доменами)
    # Используем _external=False для относительных URL (работает и на localhost, и на доменах)
    login_url = url_for('login', 
                       sso=True,
                       redirect_uri=redirect_uri,
                       client_id=client_id,
                       state=state)
    
    return redirect(login_url)

# Страница входа
@app.route('/login')
def login():
    # Если пользователь уже авторизован, редиректим на главную
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if user:
            # Если есть SSO параметры, обрабатываем их
            sso = request.args.get('sso', False)
            redirect_uri = request.args.get('redirect_uri', '')
            client_id = request.args.get('client_id', '')
            state = request.args.get('state', '')
            
            if sso and redirect_uri:
                # Пользователь уже авторизован, сразу редиректим на SSO авторизацию
                return redirect(url_for('api_quick_login_authorize', 
                                      redirect_uri=redirect_uri,
                                      client_id=client_id,
                                      state=state))
            
            # Обычный редирект на дашборд
            return redirect(url_for('index'))
    
    sso = request.args.get('sso', False)
    redirect_uri = request.args.get('redirect_uri', '')
    client_id = request.args.get('client_id', '')
    state = request.args.get('state', '')
    
    # Если это SSO запрос, сохраняем параметры в сессии для использования после авторизации
    if sso and redirect_uri:
        session['sso_redirect_uri'] = redirect_uri
        session['sso_client_id'] = client_id
        session['sso_state'] = state
    
    return render_template('login.html', 
                          sso=bool(sso),
                          redirect_uri=redirect_uri,
                          client_id=client_id,
                          state=state)

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def api_login():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    try:
        # Поддерживаем как JSON, так и form-data (для SSO через форму)
        if request.content_type and 'application/json' in request.content_type:
            data = request.json
        else:
            # Form data (для SSO)
            data = request.form.to_dict()
        
        if not data:
            return jsonify({"success": False, "error": "Неверный запрос"}), 400
            
        username_or_phone = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username_or_phone or not password:
            return jsonify({"success": False, "error": "Введите логин/телефон и пароль"}), 400
        
        conn = get_db()
        
        # Нормализация номера телефона (улучшенная)
        phone_cleaned = username_or_phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        
        # Определяем, является ли ввод номером телефона
        # Поддержка форматов: +79..., 79..., 89..., 9... (10 цифр)
        digits_only = ''.join(filter(str.isdigit, phone_cleaned))
        is_phone = False
        phone_normalized = None
        
        if phone_cleaned.startswith('+') and len(digits_only) >= 10:
            is_phone = True
            phone_normalized = phone_cleaned
        elif len(digits_only) == 11 and (digits_only.startswith('7') or digits_only.startswith('8')):
            is_phone = True
            # Приводим к формату +7...
            phone_normalized = '+7' + digits_only[1:]
        elif len(digits_only) == 10 and digits_only.startswith('9'):
            is_phone = True
            # Приводим к формату +79...
            phone_normalized = '+7' + digits_only
            
        if is_phone and phone_normalized:
            # Ищем по нормализованному номеру и возможным вариациям
            search_phones = [
                phone_normalized,
                phone_normalized[1:] if phone_normalized.startswith('+') else '+' + phone_normalized,
                digits_only
            ]
            if len(digits_only) == 11:
                if digits_only.startswith('7'):
                    search_phones.append('8' + digits_only[1:])
                elif digits_only.startswith('8'):
                    search_phones.append('7' + digits_only[1:])
            elif len(digits_only) == 10:
                search_phones.append('7' + digits_only)
                search_phones.append('8' + digits_only)
            
            # Убираем дубликаты
            search_phones = list(dict.fromkeys(search_phones))
            
            # Ищем пользователя
            placeholders = ','.join(['?'] * len(search_phones))
            user = conn.execute(
                f'SELECT * FROM users WHERE phone IN ({placeholders})', 
                tuple(search_phones)
            ).fetchone()
        else:
            # Ищем по логину
            user = conn.execute(
                'SELECT * FROM users WHERE username = ?', (username_or_phone,)
            ).fetchone()
        
        conn.close()
        
        if not user or not check_password_hash(user['password_hash'], password):
            response = jsonify({"success": False, "error": "Неверный логин или пароль"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 401
        
        # Авторизуем пользователя
        session['user_id'] = user['id']
        session['username'] = user['username']
        session.permanent = True  # Делаем сессию постоянной
        
        # Явно сохраняем сессию (Flask иногда не сохраняет автоматически)
        try:
            session.modified = True
        except:
            pass
        
        # Логируем для отладки
        print(f"User {user['username']} (ID: {user['id']}) logged in, session saved")
        print(f"Session keys after login: {list(session.keys())}")
        print(f"Session permanent: {session.permanent}")
        
        # Если это SSO запрос, перенаправляем на клиента
        # ВАЖНО: Для SSO нельзя возвращать JSON, нужно делать браузерный редирект
        if 'sso_redirect_uri' in session:
            redirect_uri = session.pop('sso_redirect_uri')
            client_id = session.pop('sso_client_id', '')
            state = session.pop('sso_state', '')
            try:
                # Браузерный редирект работает между доменами
                return redirect_to_client(redirect_uri, client_id, user['id'], state)
            except Exception as e:
                print(f"Error redirecting to client: {e}")
                import traceback
                traceback.print_exc()
                # Если ошибка, возвращаем HTML с JavaScript редиректом
                return f'''
                <!DOCTYPE html>
                <html>
                <head><title>Redirecting...</title></head>
                <body>
                    <script>
                        window.location.href = "{redirect_uri}?error=redirect_failed";
                    </script>
                    <p>Redirecting...</p>
                </body>
                </html>
                ''', 200
        
        # Обычный логин (не SSO) - возвращаем JSON
        response = jsonify({"success": True, "message": "Logged in successfully"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Login error: {e}")
        response = jsonify({"success": False, "error": "Internal server error"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

# Вход по SMS
@app.route('/api/login/sms/send', methods=['POST', 'OPTIONS'])
def api_login_sms_send():
    """Отправка SMS кода для входа или регистрации"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    try:
        data = request.json
        if not data:
            response = jsonify({"success": False, "error": "Неверный запрос"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
            
        phone = data.get('phone', '').strip()
        
        if not phone:
            response = jsonify({"success": False, "error": "Введите номер телефона"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Нормализуем номер телефона (простой вариант)
        phone_normalized = phone.replace(' ', '').replace('-', '')
        
        # Улучшенная нормализация
        if phone_normalized.startswith('+'):
            pass # OK
        elif phone_normalized.startswith('8') and len(phone_normalized) == 11:
            phone_normalized = '+7' + phone_normalized[1:]
        elif phone_normalized.startswith('7') and len(phone_normalized) == 11:
            phone_normalized = '+' + phone_normalized
        elif phone_normalized.startswith('9') and len(phone_normalized) == 10:
            phone_normalized = '+7' + phone_normalized
        
        # Проверяем, существует ли пользователь с таким номером
        conn = get_db()
        
        # Ищем по номеру телефона (пробуем разные варианты)
        search_phones = [
            phone_normalized,
            phone_normalized[1:] if phone_normalized.startswith('+') else '+' + phone_normalized,
        ]
        
        placeholders = ','.join(['?'] * len(search_phones))
        user = conn.execute(
            f'SELECT * FROM users WHERE phone IN ({placeholders})', 
            tuple(search_phones)
        ).fetchone()
        
        conn.close()
        
        # Генерируем код
        code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        
        # Отправляем SMS (даже если пользователя нет - для регистрации)
        sms_success, sms_error = send_sms_code(phone_normalized, code)
        
        if not sms_success:
            error_msg = "Ошибка отправки SMS"
            if sms_error == "not_registered":
                error_msg = "Этот номер не зарегистрирован в боте @dream_smsbot. Пожалуйста, сначала зарегистрируйтесь в боте."
            elif sms_error:
                error_msg = sms_error
            response = jsonify({"success": False, "error": error_msg})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Сохраняем код в БД
        try:
            conn = get_db()
            expires_at = datetime.now() + timedelta(minutes=CODE_EXPIRY_MINUTES)
            expires_at_str = expires_at.isoformat()
            conn.execute(
                '''INSERT OR REPLACE INTO phone_verification (phone, code, expires_at)
                   VALUES (?, ?, ?)''',
                (phone_normalized, code, expires_at_str)
            )
            conn.commit()
            conn.close()
        except sqlite3.OperationalError as e:
            print(f"Database write error: {e}")
            response = jsonify({"success": False, "error": "Ошибка базы данных"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 500
        
        # Сохраняем телефоны в сессии
        session['login_phone'] = phone_normalized
        session['register_phone'] = phone_normalized # For potential registration
        
        response = jsonify({
            "success": True, 
            "message": "Code sent to phone",
            "is_registered": bool(user)
        })
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Login SMS send error: {e}")
        print(f"Traceback: {error_trace}")
        response = jsonify({"success": False, "error": f"Internal server error: {str(e)}"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

@app.route('/api/login/sms/verify', methods=['POST', 'OPTIONS'])
def api_login_sms_verify():
    """Проверка SMS кода и авторизация"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    try:
        data = request.json
        if not data:
            response = jsonify({"success": False, "error": "Неверный запрос"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
            
        # Пытаемся получить телефон из сессии или из запроса
        phone = session.get('login_phone') or data.get('phone', '').strip()
        code = data.get('code', '').strip()
        
        if not code:
            response = jsonify({"success": False, "error": "Введите код"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Если телефона нет ни в сессии, ни в запросе, пытаемся найти по коду в БД
        conn = get_db()
        if not phone:
            now_str = datetime.now().isoformat()
            verification = conn.execute(
                'SELECT phone FROM phone_verification WHERE code = ? AND expires_at > ?',
                (code, now_str)
            ).fetchone()
            
            if verification:
                phone = verification['phone']
            else:
                conn.close()
                response = jsonify({"success": False, "error": "Телефон не найден. Введите номер заново."})
                response.headers.add('Access-Control-Allow-Origin', '*')
                return response, 400
        
        # Нормализуем номер телефона (как в send)
        phone_normalized = phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        if not phone_normalized.startswith('+'):
             # Simple logic from send
             if len(phone_normalized) == 11 and (phone_normalized.startswith('8') or phone_normalized.startswith('7')):
                 phone_normalized = '+7' + phone_normalized[1:]
             elif len(phone_normalized) == 10:
                 phone_normalized = '+7' + phone_normalized
        
        # Сначала проверяем код в нашей БД
        now_str = datetime.now().isoformat()
        db_verification = conn.execute(
            'SELECT phone, code FROM phone_verification WHERE phone = ? AND code = ? AND expires_at > ?',
            (phone_normalized, code, now_str)
        ).fetchone()
        
        # Если код не найден в БД, возвращаем ошибку
        if not db_verification:
            conn.close()
            response = jsonify({"success": False, "error": "Неверный или истекший код. Запросите новый код."})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        conn.close()
        
        # Проверяем код через SMS API для получения telegram_username
        verify_success = False
        verify_error = None
        user_data = None
        telegram_username = None
        
        try:
            verify_success, verify_error, user_data = verify_sms_code(phone_normalized, code, SMS_API_KEY)
            if verify_success and user_data and isinstance(user_data, dict):
                telegram_username = user_data.get('telegram_username')
        except Exception as e:
            print(f"Error calling verify_sms_code: {e}")
            import traceback
            traceback.print_exc()
            # Продолжаем без telegram_username, если ошибка
            verify_success = False
            verify_error = str(e)
        
        # Удаляем использованный код из БД
        try:
            conn = get_db()
            conn.execute('DELETE FROM phone_verification WHERE phone = ? AND code = ?', (phone_normalized, code))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Warning: Could not delete verification code from DB: {e}")
        
        # Получаем пользователя (пробуем разные варианты номера)
        conn = get_db()
        
        # Нормализуем для поиска (все цифры)
        digits_only = ''.join(filter(str.isdigit, phone_normalized))
        
        search_phones = [
            phone_normalized,
            phone_normalized[1:] if phone_normalized.startswith('+') else '+' + phone_normalized,
            digits_only
        ]
        
        if len(digits_only) == 11:
            if digits_only.startswith('7'):
                search_phones.append('8' + digits_only[1:])
                search_phones.append('+7' + digits_only[1:])
            elif digits_only.startswith('8'):
                search_phones.append('7' + digits_only[1:])
                search_phones.append('+7' + digits_only[1:])
        elif len(digits_only) == 10:
            search_phones.append('7' + digits_only)
            search_phones.append('8' + digits_only)
            search_phones.append('+7' + digits_only)
            
        # Убираем дубликаты
        search_phones = list(set(search_phones))
        
        placeholders = ','.join(['?'] * len(search_phones))
        user = conn.execute(
            f'SELECT * FROM users WHERE phone IN ({placeholders})', 
            tuple(search_phones)
        ).fetchone()
        conn.close()
        
        if not user:
            # Если пользователь не найден, но код верный -> это регистрация
            # Возвращаем флаг, что нужно дозаполнить профиль
            session['register_phone'] = phone_normalized
            session['phone_verified'] = phone_normalized # Mark phone as verified for step 2
            if telegram_username:
                session['telegram_username'] = telegram_username
            response = jsonify({
                "success": True, 
                "is_new_user": True, 
                "message": "Phone verified"
            })
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response
        
        # Обновляем telegram_username если он был получен и отличается от текущего
        current_telegram_username = user['telegram_username'] if user['telegram_username'] else None
        if telegram_username and telegram_username != current_telegram_username:
            try:
                conn = get_db()
                conn.execute(
                    'UPDATE users SET telegram_username = ? WHERE id = ?',
                    (telegram_username, user['id'])
                )
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Warning: Could not update telegram_username: {e}")
        
        # Авторизуем пользователя
        session['user_id'] = user['id']
        session['username'] = user['username']
        session.permanent = True
        session.pop('login_phone', None)
        
        # Сохраняем сессию явно
        try:
            session.modified = True
        except:
            pass
        
        # Если это SSO запрос, генерируем код и возвращаем URL для редиректа
        if 'sso_redirect_uri' in session:
            redirect_uri = session.pop('sso_redirect_uri')
            client_id = session.pop('sso_client_id', '')
            state = session.pop('sso_state', '')
            print(f"SMS Login SSO redirect: redirect_uri={redirect_uri}, client_id={client_id}, state={state}, user_id={user['id']}")
            try:
                # Генерируем код для SSO
                code = secrets.token_urlsafe(32)
                
                # Сохраняем код в БД
                conn = get_db()
                expires_at = datetime.now() + timedelta(minutes=SSO_CODE_EXPIRY_MINUTES)
                conn.execute(
                    'INSERT INTO sso_codes (code, user_id, redirect_uri, client_id, state, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
                    (code, user['id'], redirect_uri, client_id, state, expires_at)
                )
                conn.commit()
                conn.close()
                
                # Формируем URL для редиректа
                separator = '&' if '?' in redirect_uri else '?'
                redirect_url = f"{redirect_uri}{separator}code={code}"
                if state:
                    redirect_url += f"&state={state}"
                
                print(f"SSO redirect URL generated: {redirect_url}")
                
                # Возвращаем JSON с URL для редиректа (AJAX запрос)
                response = jsonify({
                    "success": True, 
                    "message": "Logged in successfully",
                    "redirect": redirect_url,
                    "sso": True
                })
                response.headers.add('Access-Control-Allow-Origin', '*')
                return response
            except Exception as e:
                print(f"Error generating SSO redirect: {e}")
                import traceback
                traceback.print_exc()
                response = jsonify({
                    "success": False, 
                    "error": f"SSO redirect failed: {str(e)}"
                })
                response.headers.add('Access-Control-Allow-Origin', '*')
                return response, 500
        
        response = jsonify({"success": True, "message": "Logged in successfully"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Login SMS verify error: {e}")
        import traceback
        traceback.print_exc()
        response = jsonify({"success": False, "error": f"Internal server error: {str(e)}"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

# Страница регистрации
@app.route('/register')
def register():
    # Если пользователь уже авторизован, редиректим на главную
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/api/register/simple', methods=['POST', 'OPTIONS'])
def api_register_simple():
    """Упрощенная регистрация (с опциональным телефоном)"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    try:
        data = request.json
        if not data:
            response = jsonify({"success": False, "error": "Неверный запрос"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
            
        username = data.get('username', '').strip()
        password = data.get('password', '')
        phone = data.get('phone', '').strip() if data.get('phone') else None
        
        if not username or not password:
            response = jsonify({"success": False, "error": "Введите логин и пароль"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Проверяем уникальность username
        conn = get_db()
        existing = conn.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone()
        
        if existing:
            conn.close()
            response = jsonify({"success": False, "error": "Логин уже занят"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Если указан телефон, нормализуем и проверяем уникальность
        phone_normalized = None
        if phone:
            phone_normalized = phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
            if phone_normalized.startswith('+'):
                pass
            elif phone_normalized.startswith('8') and len(phone_normalized) == 11:
                phone_normalized = '+7' + phone_normalized[1:]
            elif phone_normalized.startswith('7') and len(phone_normalized) == 11:
                phone_normalized = '+' + phone_normalized
            elif phone_normalized.startswith('9') and len(phone_normalized) == 10:
                phone_normalized = '+7' + phone_normalized
            
            # Проверяем, не занят ли номер
            search_phones = [
                phone_normalized,
                phone_normalized[1:] if phone_normalized.startswith('+') else '+' + phone_normalized,
            ]
            placeholders = ','.join(['?'] * len(search_phones))
            existing_phone = conn.execute(
                f'SELECT id FROM users WHERE phone IN ({placeholders})', 
                tuple(search_phones)
            ).fetchone()
            
            if existing_phone:
                conn.close()
                response = jsonify({"success": False, "error": "Номер телефона уже используется"})
                response.headers.add('Access-Control-Allow-Origin', '*')
                return response, 400
        
        # Создаем пользователя (phone может быть NULL)
        password_hash = generate_password_hash(password)
        if phone_normalized:
            cursor = conn.execute(
                'INSERT INTO users (username, password_hash, phone) VALUES (?, ?, ?)',
                (username, password_hash, phone_normalized)
            )
        else:
            cursor = conn.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                (username, password_hash)
            )
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Авторизуем пользователя
        session['user_id'] = user_id
        session['username'] = username
        session.permanent = True
        
        # Если это SSO запрос, перенаправляем на клиента
        if 'sso_redirect_uri' in session:
            redirect_uri = session.pop('sso_redirect_uri')
            client_id = session.pop('sso_client_id', '')
            state = session.pop('sso_state', '')
            try:
                return redirect_to_client(redirect_uri, client_id, user_id, state)
            except Exception as e:
                print(f"Error redirecting to client: {e}")
                pass
        
        response = jsonify({"success": True, "message": "Account created successfully"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Register simple error: {e}")
        response = jsonify({"success": False, "error": "Internal server error"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

@app.route('/api/register/step1', methods=['POST', 'OPTIONS'])
def api_register_step1():
    """Шаг 1: Отправка кода на телефон"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    try:
        data = request.json
        if not data:
            response = jsonify({"success": False, "error": "Неверный запрос"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
            
        phone = data.get('phone', '').strip()
        
        if not phone:
            response = jsonify({"success": False, "error": "Введите номер телефона"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Улучшение: Нормализация номера телефона
        phone_normalized = phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        
        # Проверяем, существует ли уже пользователь с таким телефоном
        conn = get_db()
        
        # Проверяем разные варианты написания номера (как в логине)
        search_phones = [
            phone,
            phone_normalized,
            '+' + phone_normalized if not phone_normalized.startswith('+') else phone_normalized,
            phone_normalized[1:] if phone_normalized.startswith('+') else phone_normalized
        ]
        if phone_normalized.isdigit():
             # Добавляем варианты с 7 и 8 если номер похож на РФ
             if len(phone_normalized) == 10:
                 search_phones.append('7' + phone_normalized)
                 search_phones.append('8' + phone_normalized)
                 search_phones.append('+7' + phone_normalized)
        
        # Убираем дубликаты
        search_phones = list(set(search_phones))
        
        placeholders = ','.join(['?'] * len(search_phones))
        existing_user = conn.execute(
            f'SELECT id FROM users WHERE phone IN ({placeholders})', 
            tuple(search_phones)
        ).fetchone()
        
        if existing_user:
            conn.close()
            response = jsonify({
                "success": False, 
                "error": "Пользователь с таким номером уже зарегистрирован",
                "code": "user_exists",
                "redirect": "/login"
            })
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 409
            
        conn.close()
        
        # Генерируем код
        code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        
        # Отправляем SMS на нормализованный номер
        sms_success, sms_error = send_sms_code(phone_normalized, code)
        if not sms_success:
            error_msg = "Ошибка отправки SMS"
            if sms_error == "not_registered":
                error_msg = "Этот номер не зарегистрирован в боте @dream_smsbot. Пожалуйста, сначала зарегистрируйтесь в боте, затем вернитесь для регистрации в dreamID."
            elif sms_error:
                error_msg = sms_error
            response = jsonify({"success": False, "error": error_msg})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Сохраняем код в БД
        conn = get_db()
        expires_at = datetime.now() + timedelta(minutes=CODE_EXPIRY_MINUTES)
        expires_at_str = expires_at.isoformat()
        conn.execute(
            '''INSERT OR REPLACE INTO phone_verification (phone, code, expires_at)
               VALUES (?, ?, ?)''',
            (phone_normalized, code, expires_at_str)
        )
        conn.commit()
        conn.close()
        
        # Сохраняем нормализованный телефон в сессии для следующего шага
        session['register_phone'] = phone_normalized
        
        response = jsonify({"success": True, "message": "Code sent to phone"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Register step1 error: {e}")
        response = jsonify({"success": False, "error": "Internal server error"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

@app.route('/api/register/step2', methods=['POST', 'OPTIONS'])
def api_register_step2():
    """Шаг 2: Проверка кода и создание аккаунта"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    try:
        data = request.json
        if not data:
            response = jsonify({"success": False, "error": "Неверный запрос"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
            
        phone = session.get('register_phone')
        # Получаем параметры
        code = data.get('code', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not phone or not code or not username or not password:
            response = jsonify({"success": False, "error": "Заполните все поля"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Проверяем, был ли телефон уже подтвержден на предыдущем шаге (в login verify)
        phone_verified_in_session = session.get('phone_verified')
        telegram_username = None
        
        if phone_verified_in_session and phone_verified_in_session == phone:
            # Телефон уже подтвержден, пропускаем повторную проверку кода
            # Но можем получить telegram_username из сессии
            telegram_username = session.get('telegram_username')
            # Также можем попробовать получить из SMS API если есть API ключ
            if not telegram_username and SMS_API_KEY:
                try:
                    _, _, user_data = verify_sms_code(phone, code, SMS_API_KEY)
                    if user_data and user_data.get('telegram_username'):
                        telegram_username = user_data['telegram_username']
                except:
                    pass
        else:
            # Проверяем код через API (если не был подтвержден ранее)
            verify_success, verify_error, user_data = verify_sms_code(phone, code, SMS_API_KEY)
            if not verify_success:
                error_msg = "Неверный или истекший код"
                if verify_error == "not_registered":
                    error_msg = "Этот номер не зарегистрирован в боте @dream_smsbot. Пожалуйста, сначала зарегистрируйтесь в боте."
                elif verify_error and verify_error != "Invalid or expired code":
                    error_msg = verify_error
                response = jsonify({"success": False, "error": error_msg})
                response.headers.add('Access-Control-Allow-Origin', '*')
                return response, 400
            
            # Получаем telegram_username из user_data если доступен
            if user_data and user_data.get('telegram_username'):
                telegram_username = user_data['telegram_username']
        
        conn = get_db()
        
        # Создаем пользователя
        password_hash = generate_password_hash(password)
        cursor = conn.execute(
            'INSERT INTO users (username, password_hash, phone, telegram_username, telegram_id) VALUES (?, ?, ?, ?, ?)',
            (username, password_hash, phone, telegram_username, None)
        )
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Очищаем временные данные
        session.pop('register_phone', None)
        
        # Авторизуем пользователя
        session['user_id'] = user_id
        session['username'] = username
        session.permanent = True
        
        # Если это SSO запрос, перенаправляем на клиента
        if 'sso_redirect_uri' in session:
            redirect_uri = session.pop('sso_redirect_uri')
            client_id = session.pop('sso_client_id', '')
            state = session.pop('sso_state', '')
            try:
                return redirect_to_client(redirect_uri, client_id, user_id, state)
            except Exception as e:
                print(f"Error redirecting to client: {e}")
                pass
        
        response = jsonify({"success": True, "message": "Account created successfully"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Register step2 error: {e}")
        response = jsonify({"success": False, "error": "Internal server error"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

# SSO функции
def redirect_to_client(redirect_uri, client_id, user_id, state=''):
    """Генерирует код и перенаправляет на клиента (OAuth 2.0 Authorization Code flow)
    
    Работает между разными доменами через браузерные редиректы.
    Это стандартный способ для OAuth 2.0 / OpenID Connect.
    """
    try:
        # Генерируем временный код (authorization code)
        code = secrets.token_urlsafe(32)
        
        print(f"Generating SSO code: code={code[:10]}..., redirect_uri={redirect_uri}, client_id={client_id}, user_id={user_id}, state={state}")
        
        # Сохраняем код в БД
        conn = get_db()
        expires_at = datetime.now() + timedelta(minutes=SSO_CODE_EXPIRY_MINUTES)
        conn.execute(
            'INSERT INTO sso_codes (code, user_id, redirect_uri, client_id, state, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
            (code, user_id, redirect_uri, client_id, state, expires_at)
        )
        conn.commit()
        conn.close()
        
        # Формируем URL для редиректа (OAuth 2.0 стандарт)
        # Добавляем code и state (если был передан)
        separator = '&' if '?' in redirect_uri else '?'
        redirect_url = f"{redirect_uri}{separator}code={code}"
        
        if state:
            redirect_url += f"&state={state}"
        
        print(f"Redirecting to: {redirect_url}")
        
        # Браузерный редирект работает между любыми доменами
        # Это стандартный OAuth 2.0 flow
        return redirect(redirect_url)
    except Exception as e:
        print(f"Error in redirect_to_client: {e}")
        import traceback
        traceback.print_exc()
        raise

# Обмен кода на токен (OAuth 2.0 Token Endpoint)
@app.route('/token', methods=['POST', 'OPTIONS'])
@app.route('/oauth/token', methods=['POST', 'OPTIONS'])
@app.route('/api/sso/token', methods=['POST', 'OPTIONS'])
def sso_token():
    """Обмен SSO кода на токен доступа (OAuth 2.0 Token Exchange)
    
    Этот endpoint вызывается с клиентского сервера (backend-to-backend),
    поэтому CORS не нужен, но настраиваем для удобства разработки.
    """
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    try:
        data = request.json
        if not data:
            response = jsonify({"error": "Invalid request"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
            
        code = data.get('code')
        client_id = data.get('client_id', '')
        client_secret = data.get('client_secret', '')
        
        if not code:
            response = jsonify({"error": "code is required"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Проверяем client_secret если client_id указан
        if client_id:
            if not client_secret:
                response = jsonify({"error": "client_secret is required"})
                response.headers.add('Access-Control-Allow-Origin', '*')
                return response, 400
            
            if not verify_client_secret(client_id, client_secret):
                response = jsonify({"error": "Invalid client_secret"})
                response.headers.add('Access-Control-Allow-Origin', '*')
                return response, 401
        
        conn = get_db()
        sso_code = conn.execute(
            'SELECT * FROM sso_codes WHERE code = ?', (code,)
        ).fetchone()
        
        if not sso_code:
            conn.close()
            response = jsonify({"error": "Invalid code"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 401
        
        # Проверяем, что client_id из кода совпадает с переданным
        if client_id and sso_code['client_id'] and sso_code['client_id'] != client_id:
            conn.close()
            response = jsonify({"error": "client_id mismatch"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 401
        
        # Проверяем срок действия
        expires_at = datetime.fromisoformat(sso_code['expires_at'])
        if datetime.now() > expires_at:
            conn.execute('DELETE FROM sso_codes WHERE code = ?', (code,))
            conn.commit()
            conn.close()
            response = jsonify({"error": "Code expired"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 401
        
        # Удаляем использованный код
        conn.execute('DELETE FROM sso_codes WHERE code = ?', (code,))
        
        # Генерируем токен
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(days=30)  # Токен на 30 дней
        
        conn.execute(
            'INSERT INTO sso_tokens (token, user_id, client_id, expires_at) VALUES (?, ?, ?, ?)',
            (token, sso_code['user_id'], client_id, expires_at)
        )
        conn.commit()
        conn.close()
        
        response = jsonify({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 30 * 24 * 60 * 60  # секунды
        })
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Token exchange error: {e}")
        response = jsonify({"error": "Internal server error"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

# Проверка токена и получение данных пользователя
@app.route('/api/user', methods=['GET', 'OPTIONS'])
@app.route('/api/sso/user', methods=['GET', 'OPTIONS'])
def sso_user():
    """Получение данных пользователя по токену"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
        return response
    
    try:
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            response = jsonify({"error": "Invalid authorization header"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 401
        
        token = auth_header[7:]  # Убираем "Bearer "
        
        conn = get_db()
        sso_token = conn.execute(
            'SELECT * FROM sso_tokens WHERE token = ?', (token,)
        ).fetchone()
        
        if not sso_token:
            conn.close()
            response = jsonify({"error": "Invalid token"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 401
        
        # Проверяем срок действия
        expires_at = datetime.fromisoformat(sso_token['expires_at'])
        if datetime.now() > expires_at:
            conn.execute('DELETE FROM sso_tokens WHERE token = ?', (token,))
            conn.commit()
            conn.close()
            response = jsonify({"error": "Token expired"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 401
        
        # Получаем данные пользователя
        user = conn.execute(
            'SELECT id, username, phone, avatar, first_name, last_name, email, country, city, telegram_username, telegram_id FROM users WHERE id = ?', 
            (sso_token['user_id'],)
        ).fetchone()
        conn.close()
        
        if not user:
            response = jsonify({"error": "User not found"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 404
        
        response = jsonify({
            "id": user['id'],
            "username": user['username'],
            "phone": user['phone'],
            "avatar": user['avatar'] if user['avatar'] else None,
            "first_name": user['first_name'] if user['first_name'] else None,
            "last_name": user['last_name'] if user['last_name'] else None,
            "email": user['email'] if user['email'] else None,
            "country": user['country'] if user['country'] else None,
            "city": user['city'] if user['city'] else None,
            "telegram_username": user['telegram_username'] if user['telegram_username'] else None,
            "telegram_id": user['telegram_id'] if user['telegram_id'] else None
        })
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Get user error: {e}")
        response = jsonify({"error": "Internal server error"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

# API для регистрации клиентов
@app.route('/api/admin/register-client', methods=['POST', 'OPTIONS'])
def register_client_api():
    """Регистрация нового клиента (требует авторизации админа)"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    try:
        data = request.json
        if not data:
            response = jsonify({"error": "Invalid request"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        name = data.get('name', '')
        allowed_redirect_uris = data.get('allowed_redirect_uris', [])
        
        if not client_id or not client_secret:
            response = jsonify({"error": "client_id and client_secret are required"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        if not allowed_redirect_uris:
            response = jsonify({"error": "allowed_redirect_uris is required (array of URLs)"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        success, message = register_client(client_id, client_secret, name, allowed_redirect_uris)
        
        if success:
            response = jsonify({"success": True, "message": message})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response
        else:
            response = jsonify({"success": False, "error": message})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
            
    except Exception as e:
        print(f"Register client error: {e}")
        response = jsonify({"error": "Internal server error"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

# Быстрый вход через Telegram
@app.route('/api/quick-login/generate', methods=['POST', 'OPTIONS'])
def api_quick_login_generate():
    """Генерация токена для быстрого входа через Telegram"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    try:
        data = request.json or {}
        redirect_uri = data.get('redirect_uri', '')
        client_id = data.get('client_id', '')
        state = data.get('state', '')
        
        # Генерируем токен
        token = secrets.token_urlsafe(32)
        
        # Сохраняем токен в БД
        conn = get_db()
        expires_at = datetime.now() + timedelta(minutes=QUICK_LOGIN_TOKEN_EXPIRY_MINUTES)
        conn.execute(
            'INSERT INTO quick_login_tokens (token, redirect_uri, client_id, state, expires_at) VALUES (?, ?, ?, ?, ?)',
            (token, redirect_uri, client_id, state, expires_at)
        )
        conn.commit()
        conn.close()
        
        # Формируем ссылку для бота
        bot_username = 'dream_smsbot'  # Имя бота из sms/bot.py
        bot_link = f"https://t.me/{bot_username}?start=quick_login_{token}"
        
        response = jsonify({
            "success": True,
            "token": token,
            "bot_link": bot_link
        })
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Quick login generate error: {e}")
        response = jsonify({"success": False, "error": "Internal server error"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

@app.route('/api/quick-login/auth', methods=['GET'])
def api_quick_login_auth():
    """Авторизация по токену быстрого входа (устаревший endpoint, используется /quick-login/authorize)"""
    return redirect(url_for('api_quick_login_authorize', token=request.args.get('token')))

@app.route('/api/quick-login/verify', methods=['POST', 'OPTIONS'])
def api_quick_login_verify():
    """Проверка токена и авторизация пользователя (вызывается ботом)"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    try:
        data = request.json
        if not data:
            print("[Quick Login Verify] No data in request")
            response = jsonify({"success": False, "error": "Invalid request"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        token = data.get('token')
        user_id = data.get('user_id')  # Telegram user_id
        phone = data.get('phone')  # Телефон от бота (опционально, для упрощения)
        telegram_username_from_bot = data.get('telegram_username')  # Передан напрямую из бота
        avatar_file_id_from_bot = data.get('avatar_file_id')  # file_id аватара из Telegram
        first_name_from_bot = data.get('first_name')  # Имя из бота
        telegram_id = user_id  # Сохраняем Telegram ID
        
        print(f"[Quick Login Verify] Token: {token[:10] if token else 'None'}..., user_id: {user_id}, phone: {phone}, username_from_bot: {telegram_username_from_bot}")
        
        if not token or not user_id:
            print("[Quick Login Verify] Missing token or user_id")
            response = jsonify({"success": False, "error": "Token and user_id required"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Проверяем токен
        conn = get_db()
        token_data = conn.execute(
            'SELECT * FROM quick_login_tokens WHERE token = ?', (token,)
        ).fetchone()
        
        if not token_data:
            conn.close()
            print(f"[Quick Login Verify] Invalid token: {token[:10]}...")
            response = jsonify({"success": False, "error": "Токен истек или некорректный. Попробуйте войти еще раз."})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        print(f"[Quick Login Verify] Token found, expires_at: {token_data['expires_at']}")
        
        # Проверяем срок действия
        expires_at = datetime.fromisoformat(token_data['expires_at'])
        if datetime.now() > expires_at:
            conn.execute('DELETE FROM quick_login_tokens WHERE token = ?', (token,))
            conn.commit()
            conn.close()
            print(f"[Quick Login Verify] Token expired")
            response = jsonify({"success": False, "error": "Токен истек. Попробуйте войти еще раз."})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Ищем пользователя в auth системе по телефону
        # Сначала пробуем использовать телефон, переданный ботом
        user = None
        if phone:
            print(f"[Quick Login Verify] Searching user by phone from bot: {phone}")
            search_phones = [
                phone,
                '+' + phone if not phone.startswith('+') else phone,
                phone[1:] if phone.startswith('+') else phone
            ]
            # Нормализуем номера
            normalized_phones = []
            for p in search_phones:
                digits = ''.join(filter(str.isdigit, p))
                if digits.startswith('7') and len(digits) == 11:
                    normalized_phones.extend(['+' + digits, '7' + digits[1:], '8' + digits[1:]])
                elif digits.startswith('8') and len(digits) == 11:
                    normalized_phones.extend(['+7' + digits[1:], digits, '7' + digits[1:]])
                else:
                    normalized_phones.append(p)
            
            normalized_phones = list(set(normalized_phones))
            placeholders = ','.join(['?'] * len(normalized_phones))
            user = conn.execute(
                f'SELECT * FROM users WHERE phone IN ({placeholders})', 
                tuple(normalized_phones)
            ).fetchone()
        
        # Если не нашли по телефону от бота, пробуем через API SMS
        if not user:
            print(f"[Quick Login Verify] User not found by phone, trying SMS API for user_id: {user_id}")
            import requests
            sms_base_url = os.environ.get('SMS_BASE_URL', 'https://sms.dreampartners.online')
            sms_api_url = f"{sms_base_url}/api/user/by-telegram-id"
            try:
                sms_response = requests.post(
                    sms_api_url,
                    json={"telegram_user_id": user_id},
                    timeout=5
                )
                print(f"[Quick Login Verify] SMS API response: {sms_response.status_code}")
                if sms_response.status_code == 200:
                    sms_data = sms_response.json()
                    phone = sms_data.get('phone_number')
                    print(f"[Quick Login Verify] Got phone from SMS API: {phone}")
                    
                    if phone:
                        # Ищем пользователя в auth по телефону
                        search_phones = [
                            phone,
                            '+' + phone if not phone.startswith('+') else phone,
                            phone[1:] if phone.startswith('+') else phone
                        ]
                        # Нормализуем
                        normalized_phones = []
                        for p in search_phones:
                            digits = ''.join(filter(str.isdigit, p))
                            if digits.startswith('7') and len(digits) == 11:
                                normalized_phones.extend(['+' + digits, '7' + digits[1:], '8' + digits[1:]])
                            elif digits.startswith('8') and len(digits) == 11:
                                normalized_phones.extend(['+7' + digits[1:], digits, '7' + digits[1:]])
                            else:
                                normalized_phones.append(p)
                        
                        normalized_phones = list(set(normalized_phones))
                        placeholders = ','.join(['?'] * len(normalized_phones))
                        user = conn.execute(
                            f'SELECT * FROM users WHERE phone IN ({placeholders})', 
                            tuple(normalized_phones)
                        ).fetchone()
                else:
                    print(f"[Quick Login Verify] SMS API error: {sms_response.status_code} - {sms_response.text[:200]}")
            except Exception as e:
                print(f"[Quick Login Verify] Error getting phone from SMS bot: {e}")
                import traceback
                traceback.print_exc()
        
        if not user:
            # Пользователь не найден - создаем автоматически (регистрация через Telegram)
            print(f"[Quick Login Verify] User not found, creating new user for user_id: {user_id}, phone: {phone}")
            
            if not phone:
                conn.close()
                response = jsonify({
                    "success": False, 
                    "error": "Phone number is required for registration"
                })
                response.headers.add('Access-Control-Allow-Origin', '*')
                return response, 400
            
            # Нормализуем номер телефона
            phone_normalized = phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
            if not phone_normalized.startswith('+'):
                if len(phone_normalized) == 11 and (phone_normalized.startswith('8') or phone_normalized.startswith('7')):
                    phone_normalized = '+7' + phone_normalized[1:]
                elif len(phone_normalized) == 10:
                    phone_normalized = '+7' + phone_normalized
            
            # Получаем данные: СНАЧАЛА из переданных ботом (самый надежный источник), затем из SMS API
            telegram_username = telegram_username_from_bot  # Приоритет данным из бота
            first_name = first_name_from_bot
            avatar_file_id = avatar_file_id_from_bot
            
            # Если не переданы из бота, пробуем получить из SMS API
            if not telegram_username or not first_name:
                try:
                    sms_base_url = os.environ.get('SMS_BASE_URL', 'https://sms.dreampartners.online')
                    sms_api_url = f"{sms_base_url}/api/user/by-telegram-id"
                    sms_response = requests.post(
                        sms_api_url,
                        json={"telegram_user_id": user_id},
                        timeout=5
                    )
                    if sms_response.status_code == 200:
                        sms_data = sms_response.json()
                        if not telegram_username:
                            telegram_username = sms_data.get('username')
                        if not first_name:
                            first_name = sms_data.get('first_name')
                        print(f"[Quick Login Verify] Got from SMS API: username={telegram_username}, first_name={first_name}")
                except Exception as e:
                    print(f"[Quick Login Verify] Could not get user data from SMS API: {e}")
            
            # Генерируем avatar URL из file_id если он есть
            avatar_url = None
            if avatar_file_id:
                # Сохраняем file_id как есть, фронтенд будет получать URL через SMS API
                avatar_url = f"tg://avatar/{avatar_file_id}"
            
            print(f"[Quick Login Verify] Final: username={telegram_username}, first_name={first_name}, avatar_file_id={avatar_file_id}")
            
            # Проверяем, нет ли уже пользователя с таким телефоном (на случай параллельных запросов)
            digits_only = ''.join(filter(str.isdigit, phone_normalized))
            search_phones = [
                phone_normalized,
                phone_normalized[1:] if phone_normalized.startswith('+') else '+' + phone_normalized,
                digits_only
            ]
            if len(digits_only) == 11:
                if digits_only.startswith('7'):
                    search_phones.append('8' + digits_only[1:])
                    search_phones.append('+7' + digits_only[1:])
                elif digits_only.startswith('8'):
                    search_phones.append('7' + digits_only[1:])
                    search_phones.append('+7' + digits_only[1:])
            elif len(digits_only) == 10:
                search_phones.append('7' + digits_only)
                search_phones.append('8' + digits_only)
                search_phones.append('+7' + digits_only)
            search_phones = list(set(search_phones))
            
            placeholders = ','.join(['?'] * len(search_phones))
            existing_user = conn.execute(
                f'SELECT * FROM users WHERE phone IN ({placeholders})', 
                tuple(search_phones)
            ).fetchone()
            
            if existing_user:
                # Пользователь уже существует - используем его
                user = existing_user
                print(f"[Quick Login Verify] Found existing user: {user['username']} (ID: {user['id']})")
            else:
                # Определяем логин: используем telegram_username (уже получен выше из бота или SMS API)
                if telegram_username:
                    # Используем nickname из Telegram
                    base_username = telegram_username
                    print(f"[Quick Login Verify] Using Telegram username as login: {base_username}")
                else:
                    # Используем номер телефона как логин (только цифры без +)
                    phone_digits = ''.join(filter(str.isdigit, phone_normalized))
                    base_username = phone_digits
                    print(f"[Quick Login Verify] Using phone number as login: {base_username}")
                
                # Проверяем, не занят ли логин, если да - добавляем суффикс
                username = base_username
                counter = 1
                while True:
                    existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
                    if not existing:
                        break
                    username = f"{base_username}_{counter}"
                    counter += 1
            
                # Создаем пользователя с пустым паролем (для входа только через Telegram/SMS)
                # Используем хеш пустого пароля или случайного
                empty_password_hash = generate_password_hash('')
                
                try:
                    conn.execute(
                        'INSERT INTO users (username, password_hash, phone, telegram_username, telegram_id, first_name, avatar, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                        (username, empty_password_hash, phone_normalized, telegram_username or None, telegram_id, first_name or None, avatar_url or None, datetime.now())
                    )
                    conn.commit()
                    
                    # Получаем созданного пользователя
                    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
                    print(f"[Quick Login Verify] Created new user: {username} (ID: {user['id']})")
                except Exception as e:
                    conn.close()
                    print(f"[Quick Login Verify] Error creating user: {e}")
                    import traceback
                    traceback.print_exc()
                    response = jsonify({
                        "success": False, 
                        "error": "Failed to create user",
                        "details": str(e)
                    })
                    response.headers.add('Access-Control-Allow-Origin', '*')
                    return response, 500
        
        print(f"[Quick Login Verify] User found: {user['username']} (ID: {user['id']})")
        
        # Генерируем ссылку для авторизации
        redirect_uri = token_data['redirect_uri'] or '/'
        client_id = token_data['client_id'] or ''
        state = token_data['state'] or ''
        
        # Удаляем токен
        conn.execute('DELETE FROM quick_login_tokens WHERE token = ?', (token,))
        conn.commit()
        conn.close()
        
        # Генерируем SSO код для авторизации
        code = secrets.token_urlsafe(32)
        conn = get_db()
        expires_at = datetime.now() + timedelta(minutes=SSO_CODE_EXPIRY_MINUTES)
        conn.execute(
            'INSERT INTO sso_codes (code, user_id, redirect_uri, client_id, state, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
            (code, user['id'], redirect_uri, client_id, state, expires_at)
        )
        conn.commit()
        conn.close()
        
        # Формируем URL для авторизации (всегда через промежуточный endpoint на нашем домене)
        # Это решает проблему с localhost/http ссылками в Telegram кнопках
        # Используем AUTH_BASE_URL из конфигурации
        auth_base = AUTH_BASE_URL.rstrip('/')
        auth_url = f"{auth_base}/quick-login/authorize?code={code}"
        
        print(f"[Quick Login Verify] Success! Auth URL: {auth_url[:100]}...")
        
        response = jsonify({
            "success": True,
            "auth_url": auth_url,
            "user_id": user['id'],
            "username": user['username']
        })
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"[Quick Login Verify] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        response = jsonify({
            "success": False, 
            "error": "Internal server error",
            "details": str(e)
        })
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

@app.route('/quick-login/authorize')
def api_quick_login_authorize():
    """Авторизация пользователя по токену (прямая ссылка)"""
    token = request.args.get('token')
    code = request.args.get('code')
    
    if not token and not code:
        return redirect(url_for('login') + '?error=' + 'Токен не указан')
    
    # Если есть code, это SSO код (основной способ авторизации)
    if code:
        conn = get_db()
        sso_code = conn.execute(
            'SELECT * FROM sso_codes WHERE code = ?', (code,)
        ).fetchone()
        
        if sso_code:
            expires_at = datetime.fromisoformat(sso_code['expires_at'])
            if datetime.now() <= expires_at:
                # Авторизуем пользователя
                session['user_id'] = sso_code['user_id']
                user = conn.execute(
                    'SELECT username FROM users WHERE id = ?', (sso_code['user_id'],)
                ).fetchone()
                if user:
                    session['username'] = user['username']
                session.permanent = True
                session.modified = True
                
                # Удаляем использованный код
                conn.execute('DELETE FROM sso_codes WHERE code = ?', (code,))
                conn.commit()
                
                # Если есть redirect_uri, генерируем новый код для клиента
                redirect_uri = sso_code['redirect_uri']
                if redirect_uri:
                    # Генерируем новый код для SSO
                    new_code = secrets.token_urlsafe(32)
                    expires_at = datetime.now() + timedelta(minutes=SSO_CODE_EXPIRY_MINUTES)
                    conn.execute(
                        'INSERT INTO sso_codes (code, user_id, redirect_uri, client_id, state, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
                        (new_code, sso_code['user_id'], redirect_uri, sso_code['client_id'], sso_code['state'], expires_at)
                    )
                    conn.commit()
                    
                    separator = '&' if '?' in redirect_uri else '?'
                    final_url = f"{redirect_uri}{separator}code={new_code}"
                    if sso_code['state']:
                        final_url += f"&state={sso_code['state']}"
                    
                    conn.close()
                    return redirect(final_url)
                
                conn.close()
                return redirect(url_for('index'))
        
        conn.close()
    
    # Если передан только token (устаревший способ)
    if token:
        return redirect(url_for('login') + '?error=' + 'Используйте ссылку из бота для входа')
    
    return redirect(url_for('login') + '?error=' + 'Неверный или истекший токен')

# Привязка номера телефона
@app.route('/api/user/bind-phone/send', methods=['POST', 'OPTIONS'])
def api_bind_phone_send():
    """Отправка кода для привязки номера телефона"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    try:
        # Проверяем авторизацию
        user_id = session.get('user_id')
        if not user_id:
            response = jsonify({"success": False, "error": "Not authenticated"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 401
        
        data = request.json
        if not data:
            response = jsonify({"success": False, "error": "Invalid request"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        phone = data.get('phone', '').strip()
        if not phone:
            response = jsonify({"success": False, "error": "Phone required"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Нормализуем номер
        phone_normalized = phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        if phone_normalized.startswith('+'):
            pass
        elif phone_normalized.startswith('8') and len(phone_normalized) == 11:
            phone_normalized = '+7' + phone_normalized[1:]
        elif phone_normalized.startswith('7') and len(phone_normalized) == 11:
            phone_normalized = '+' + phone_normalized
        elif phone_normalized.startswith('9') and len(phone_normalized) == 10:
            phone_normalized = '+7' + phone_normalized
        
        # Проверяем, не занят ли номер другим пользователем
        conn = get_db()
        search_phones = [
            phone_normalized,
            phone_normalized[1:] if phone_normalized.startswith('+') else '+' + phone_normalized,
        ]
        placeholders = ','.join(['?'] * len(search_phones))
        existing_user = conn.execute(
            f'SELECT id FROM users WHERE phone IN ({placeholders}) AND id != ?', 
            tuple(search_phones + [user_id])
        ).fetchone()
        
        if existing_user:
            conn.close()
            response = jsonify({"success": False, "error": "Phone number already used by another user"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        conn.close()
        
        # Генерируем код
        code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        
        # Отправляем SMS
        sms_success, sms_error = send_sms_code(phone_normalized, code)
        if not sms_success:
            error_msg = "Ошибка отправки SMS"
            if sms_error == "not_registered":
                error_msg = "Этот номер не зарегистрирован в боте @dream_smsbot. Пожалуйста, сначала зарегистрируйтесь в боте."
            elif sms_error:
                error_msg = sms_error
            response = jsonify({"success": False, "error": error_msg})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Сохраняем код в БД
        conn = get_db()
        expires_at = datetime.now() + timedelta(minutes=CODE_EXPIRY_MINUTES)
        expires_at_str = expires_at.isoformat()
        conn.execute(
            '''INSERT OR REPLACE INTO phone_verification (phone, code, expires_at)
               VALUES (?, ?, ?)''',
            (phone_normalized, code, expires_at_str)
        )
        conn.commit()
        conn.close()
        
        # Сохраняем телефон в сессии для следующего шага
        session['bind_phone'] = phone_normalized
        
        response = jsonify({"success": True, "message": "Code sent to phone"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Bind phone send error: {e}")
        response = jsonify({"success": False, "error": "Internal server error"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

@app.route('/api/user/bind-phone/verify', methods=['POST', 'OPTIONS'])
def api_bind_phone_verify():
    """Проверка кода и привязка номера телефона"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    try:
        # Проверяем авторизацию
        user_id = session.get('user_id')
        if not user_id:
            response = jsonify({"success": False, "error": "Not authenticated"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 401
        
        data = request.json
        if not data:
            response = jsonify({"success": False, "error": "Invalid request"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        phone = session.get('bind_phone')
        code = data.get('code', '').strip()
        
        if not phone or not code:
            response = jsonify({"success": False, "error": "Phone and code required"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Проверяем код в БД
        conn = get_db()
        verification = conn.execute(
            'SELECT phone, code FROM phone_verification WHERE phone = ? AND code = ? AND expires_at > ?',
            (phone, code, datetime.now())
        ).fetchone()
        
        if not verification:
            conn.close()
            response = jsonify({"success": False, "error": "Неверный или истекший код"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Привязываем номер к пользователю
        conn.execute(
            'UPDATE users SET phone = ? WHERE id = ?',
            (phone, user_id)
        )
        conn.commit()
        conn.close()
        
        # Удаляем использованный код
        try:
            conn = get_db()
            conn.execute('DELETE FROM phone_verification WHERE phone = ? AND code = ?', (phone, code))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Warning: Could not delete verification code: {e}")
        
        # Очищаем сессию (только данные привязки)
        session.pop('bind_phone', None)
        
        # Обновляем данные пользователя в текущей сессии, чтобы не выкидывало
        session.modified = True
        
        response = jsonify({"success": True, "message": "Phone number bound successfully"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Bind phone verify error: {e}")
        response = jsonify({"success": False, "error": "Internal server error"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

# Выход
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Favicon (чтобы не было 404)
@app.route('/favicon.ico')
def favicon():
    return '', 204

# Документация
@app.route('/docs')
def docs():
    return render_template('docs.html')

# API для получения профиля пользователя
@app.route('/api/user/profile', methods=['GET', 'OPTIONS'])
def api_user_profile():
    """Получение профиля текущего пользователя"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
        return response
    
    if 'user_id' not in session:
        response = jsonify({"success": False, "error": "Не авторизован"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 401
    
    try:
        conn = get_db()
        user = conn.execute(
            'SELECT id, username, phone, avatar, first_name, last_name, email, country, city, telegram_username FROM users WHERE id = ?', 
            (session['user_id'],)
        ).fetchone()
        conn.close()
        
        if not user:
            response = jsonify({"success": False, "error": "Пользователь не найден"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 404
        
        telegram_username = user['telegram_username'] if user['telegram_username'] else None
        
        # Если telegram_username не сохранен, но есть телефон, пытаемся получить из SMS API
        if not telegram_username and user['phone'] and SMS_API_KEY:
            try:
                sms_response = requests.post(
                    f"{SMS_API_URL}/get-avatar",
                    json={"phone": user['phone']},
                    headers={"X-API-Key": SMS_API_KEY},
                    timeout=5
                )
                if sms_response.status_code == 200:
                    sms_data = sms_response.json()
                    # Получаем username из ответа (может быть в success или error случае)
                    telegram_username = sms_data.get('username')
                    if telegram_username:
                        # Сохраняем в БД
                        conn = get_db()
                        conn.execute(
                            'UPDATE users SET telegram_username = ? WHERE id = ?',
                            (telegram_username, user['id'])
                        )
                        conn.commit()
                        conn.close()
            except Exception as e:
                print(f"Could not fetch telegram_username from SMS API: {e}")
        
        response = jsonify({
            "success": True,
            "user": {
                "id": user['id'],
                "username": user['username'],
                "phone": user['phone'],
                "avatar": user['avatar'] if user['avatar'] else None,
                "first_name": user['first_name'] if user['first_name'] else None,
                "last_name": user['last_name'] if user['last_name'] else None,
                "email": user['email'] if user['email'] else None,
                "country": user['country'] if user['country'] else None,
                "city": user['city'] if user['city'] else None,
                "telegram_username": telegram_username
            }
        })
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Profile error: {e}")
        response = jsonify({"success": False, "error": "Ошибка сервера"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

# API для обновления профиля
@app.route('/api/user/profile', methods=['POST', 'PUT', 'OPTIONS'])
def api_user_profile_update():
    """Обновление профиля пользователя"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, PUT, OPTIONS')
        return response
    
    if 'user_id' not in session:
        response = jsonify({"success": False, "error": "Не авторизован"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 401
    
    try:
        data = request.json
        if not data:
            response = jsonify({"success": False, "error": "Неверный запрос"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Валидация email если передан
        email = data.get('email', '').strip() if data.get('email') else None
        if email and '@' not in email:
            response = jsonify({"success": False, "error": "Неверный формат email"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Обновляем только переданные поля
        conn = get_db()
        updates = []
        values = []
        
        allowed_fields = ['first_name', 'last_name', 'email', 'country', 'city', 'telegram_username']
        for field in allowed_fields:
            if field in data:
                value = data[field].strip() if data[field] else None
                updates.append(f"{field} = ?")
                values.append(value)
        
        if updates:
            values.append(session['user_id'])
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            conn.execute(query, tuple(values))
            conn.commit()
        
        conn.close()
        
        response = jsonify({
            "success": True,
            "message": "Профиль обновлен"
        })
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Profile update error: {e}")
        response = jsonify({"success": False, "error": "Ошибка сервера"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

# API для обновления аватара
@app.route('/api/user/avatar', methods=['POST', 'OPTIONS'])
def api_user_avatar():
    """Обновление аватара пользователя"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    if 'user_id' not in session:
        response = jsonify({"success": False, "error": "Не авторизован"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 401
    
    try:
        data = request.json
        if not data:
            response = jsonify({"success": False, "error": "Неверный запрос"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        avatar_url = data.get('avatar', '').strip()
        
        # Валидация URL аватара
        if avatar_url and not (avatar_url.startswith('http://') or avatar_url.startswith('https://')):
            response = jsonify({"success": False, "error": "Неверный формат URL"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        conn = get_db()
        conn.execute(
            'UPDATE users SET avatar = ? WHERE id = ?',
            (avatar_url if avatar_url else None, session['user_id'])
        )
        conn.commit()
        conn.close()
        
        response = jsonify({
            "success": True,
            "message": "Аватар обновлен",
            "avatar": avatar_url if avatar_url else None
        })
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    except Exception as e:
        print(f"Avatar update error: {e}")
        response = jsonify({"success": False, "error": "Ошибка сервера"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

# API для получения аватара из Telegram через SMS сервис
@app.route('/api/user/avatar/telegram', methods=['POST', 'OPTIONS'])
def api_user_avatar_telegram():
    """Получение аватара из Telegram через SMS сервис"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
    
    if 'user_id' not in session:
        response = jsonify({"success": False, "error": "Не авторизован"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 401
    
    try:
        conn = get_db()
        user = conn.execute(
            'SELECT phone FROM users WHERE id = ?', 
            (session['user_id'],)
        ).fetchone()
        conn.close()
        
        if not user or not user['phone']:
            response = jsonify({"success": False, "error": "Телефон не привязан"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
        
        # Запрос к SMS API для получения аватара
        try:
            sms_response = requests.post(
                f"{SMS_API_URL}/get-avatar",
                json={"phone": user['phone']},
                headers={"X-API-Key": SMS_API_KEY} if SMS_API_KEY else {},
                timeout=10
            )
            
            print(f"SMS API response status: {sms_response.status_code}")
            print(f"SMS API response: {sms_response.text}")
            
            if sms_response.status_code == 200:
                sms_data = sms_response.json()
                if sms_data.get('success') and sms_data.get('avatar_url'):
                    # Сохраняем аватар
                    conn = get_db()
                    conn.execute(
                        'UPDATE users SET avatar = ? WHERE id = ?',
                        (sms_data['avatar_url'], session['user_id'])
                    )
                    conn.commit()
                    conn.close()
                    
                    response = jsonify({
                        "success": True,
                        "avatar": sms_data['avatar_url'],
                        "message": "Аватар получен из Telegram"
                    })
                    response.headers.add('Access-Control-Allow-Origin', '*')
                    return response
                else:
                    error_msg = sms_data.get('error', 'Не удалось получить аватар')
                    print(f"SMS API error: {error_msg}")
                    response = jsonify({"success": False, "error": error_msg})
                    response.headers.add('Access-Control-Allow-Origin', '*')
                    return response, 400
            elif sms_response.status_code == 404:
                # SMS сервис недоступен или endpoint не найден
                error_msg = "SMS сервис недоступен. Убедитесь, что сервис запущен или используйте загрузку файла."
                print(f"SMS API error: {error_msg}")
                response = jsonify({"success": False, "error": error_msg})
                response.headers.add('Access-Control-Allow-Origin', '*')
                return response, 503  # Service Unavailable
            else:
                # Пытаемся получить сообщение об ошибке
                try:
                    error_data = sms_response.json()
                    error_msg = error_data.get('error', f'Ошибка SMS сервиса: {sms_response.status_code}')
                except:
                    if sms_response.status_code == 404:
                        error_msg = "SMS сервис недоступен. Убедитесь, что сервис запущен."
                    else:
                        error_msg = f'Ошибка SMS сервиса: {sms_response.status_code}'
                
                print(f"SMS API error: {error_msg}")
                response = jsonify({"success": False, "error": error_msg})
                response.headers.add('Access-Control-Allow-Origin', '*')
                return response, 400
        except requests.exceptions.ConnectionError as e:
            print(f"SMS API connection error: {e}")
            response = jsonify({"success": False, "error": "SMS сервис недоступен. Проверьте, что сервис запущен."})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 503
        except requests.RequestException as e:
            print(f"SMS API request error: {e}")
            response = jsonify({"success": False, "error": f"Ошибка соединения с SMS сервисом: {str(e)}"})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 500
            
    except Exception as e:
        print(f"Telegram avatar error: {e}")
        response = jsonify({"success": False, "error": "Ошибка сервера"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

# Главная страница (если зайти напрямую)
@app.route('/')
def index():
    if 'user_id' in session:
        # Получаем данные пользователя
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if user:
            # Безопасное получение полей (sqlite3.Row не имеет метода get)
            def safe_get(field):
                try:
                    return user[field] if user[field] else None
                except (KeyError, IndexError):
                    return None
            
            return render_template('dashboard.html', 
                                 username=user['username'], 
                                 phone=safe_get('phone'),
                                 avatar=safe_get('avatar'),
                                 first_name=safe_get('first_name'),
                                 last_name=safe_get('last_name'),
                                 email=safe_get('email'),
                                 country=safe_get('country'),
                                 city=safe_get('city'),
                                 telegram_username=safe_get('telegram_username'))
            
    return redirect(url_for('login'))

# ==================== ADMIN PANEL ROUTES ====================

# Admin configuration
ADMIN_CLIENT_ID = 'auth_admin'
ADMIN_CLIENT_SECRET = os.environ.get('ADMIN_CLIENT_SECRET', '')
ADMIN_TELEGRAM_ID = int(os.environ.get('ADMIN_TELEGRAM_ID', '0'))

def admin_required(f):
    """Декоратор для проверки авторизации админа"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_authenticated' not in session or not session['admin_authenticated']:
            if request.path.startswith('/api/admin/'):
                return jsonify({'error': 'Требуется авторизация'}), 401
            return redirect(url_for('admin_login'))
        
        if session.get('admin_telegram_id') != ADMIN_TELEGRAM_ID:
            session.clear()
            return redirect(url_for('admin_login'))
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Главная страница админки"""
    return render_template('auth_admin_dashboard.html')

@app.route('/admin/login')
def admin_login():
    """Страница входа в админку"""
    if session.get('admin_authenticated') and session.get('admin_telegram_id') == ADMIN_TELEGRAM_ID:
        return redirect(url_for('admin_dashboard'))
    
    return render_template('auth_admin_login.html', 
                         dreamid_auth_url=AUTH_BASE_URL,
                         client_id=ADMIN_CLIENT_ID)

@app.route('/admin/auth/callback')
def admin_auth_callback():
    """Callback от DreamID SSO для админки"""
    code = request.args.get('code')
    
    if not code:
        return redirect(url_for('admin_login'))
    
    try:
        token_url = f"{AUTH_BASE_URL}/oauth/token"
        response = requests.post(token_url, json={
            'client_id': ADMIN_CLIENT_ID,
            'client_secret': ADMIN_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code'
        }, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            access_token = data.get('access_token')
            
            user_url = f"{AUTH_BASE_URL}/api/user"
            user_response = requests.get(user_url, headers={
                'Authorization': f'Bearer {access_token}'
            }, timeout=10)
            
            if user_response.status_code == 200:
                user_data = user_response.json()
                telegram_id = user_data.get('telegram_id')
                
                if telegram_id == ADMIN_TELEGRAM_ID:
                    session['admin_authenticated'] = True
                    session['admin_username'] = user_data.get('username', 'admin')
                    session['admin_telegram_id'] = telegram_id
                    return redirect(url_for('admin_dashboard'))
                else:
                    return render_template('auth_admin_login.html', 
                                         error=f'Доступ запрещен. Только для Telegram ID: {ADMIN_TELEGRAM_ID}',
                                         dreamid_auth_url=AUTH_BASE_URL,
                                         client_id=ADMIN_CLIENT_ID)
    except Exception as e:
        print(f"Ошибка авторизации админа: {e}")
        return render_template('auth_admin_login.html', 
                             error='Ошибка авторизации',
                             dreamid_auth_url=AUTH_BASE_URL,
                             client_id=ADMIN_CLIENT_ID)
    
    return redirect(url_for('admin_login'))

@app.route('/admin/logout')
def admin_logout():
    """Выход из админки"""
    session.pop('admin_authenticated', None)
    session.pop('admin_username', None)
    session.pop('admin_telegram_id', None)
    return redirect(url_for('admin_login'))

# Admin API endpoints
@app.route('/api/admin/stats')
@admin_required
def api_admin_stats():
    """Статистика для админки"""
    conn = get_db()
    
    total_users = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()['count']
    total_clients = conn.execute("SELECT COUNT(*) as count FROM clients").fetchone()['count']
    active_tokens = conn.execute("SELECT COUNT(*) as count FROM sso_tokens WHERE datetime(expires_at) > datetime('now')").fetchone()['count']
    auth_24h = conn.execute("SELECT COUNT(*) as count FROM sso_codes WHERE datetime(created_at) > datetime('now', '-24 hours')").fetchone()['count']
    
    conn.close()
    
    return jsonify({
        'total_users': total_users,
        'total_clients': total_clients,
        'active_tokens': active_tokens,
        'auth_24h': auth_24h
    })

@app.route('/api/admin/clients')
@admin_required
def api_admin_clients():
    """Список OAuth клиентов"""
    conn = get_db()
    
    clients = conn.execute("""
        SELECT client_id, client_secret, name, allowed_redirect_uris, created_at
        FROM clients
        ORDER BY created_at DESC
    """).fetchall()
    
    conn.close()
    
    result = []
    for client in clients:
        import json
        try:
            uris = json.loads(client['allowed_redirect_uris'])
        except:
            uris = [client['allowed_redirect_uris']]
        
        result.append({
            'client_id': client['client_id'],
            'client_secret': client['client_secret'],
            'name': client['name'],
            'redirect_uris': uris,
            'created_at': client['created_at']
        })
    
    return jsonify({'clients': result})

@app.route('/api/admin/clients', methods=['POST'])
@admin_required
def api_admin_create_client():
    """Создание нового OAuth клиента"""
    data = request.json
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    name = data.get('name')
    redirect_uris = data.get('redirect_uris', [])
    
    if not client_id or not client_secret:
        return jsonify({'error': 'client_id и client_secret обязательны'}), 400
    
    import json
    uris_json = json.dumps(redirect_uris)
    
    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO clients (client_id, client_secret, name, allowed_redirect_uris)
            VALUES (?, ?, ?, ?)
        """, (client_id, client_secret, name, uris_json))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'client_id': client_id})
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/clients/<client_id>', methods=['PUT'])
@admin_required
def api_admin_update_client(client_id):
    """Обновление OAuth клиента"""
    data = request.json
    client_secret = data.get('client_secret')
    name = data.get('name')
    redirect_uris = data.get('redirect_uris', [])
    
    if not client_secret:
        return jsonify({'error': 'client_secret обязателен'}), 400
    
    import json
    uris_json = json.dumps(redirect_uris)
    
    conn = get_db()
    try:
        conn.execute("""
            UPDATE clients 
            SET client_secret = ?, name = ?, allowed_redirect_uris = ?
            WHERE client_id = ?
        """, (client_secret, name, uris_json, client_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/clients/<client_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_client(client_id):
    """Удаление OAuth клиента"""
    conn = get_db()
    conn.execute('DELETE FROM clients WHERE client_id = ?', (client_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/admin/clients/<client_id>/regenerate-secret', methods=['POST'])
@admin_required
def api_admin_regenerate_secret(client_id):
    """Перегенерация client_secret"""
    import secrets
    new_secret = secrets.token_urlsafe(32)
    
    conn = get_db()
    conn.execute('UPDATE clients SET client_secret = ? WHERE client_id = ?', (new_secret, client_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'client_secret': new_secret})

@app.route('/api/admin/users')
@admin_required
def api_admin_users():
    """Список пользователей"""
    conn = get_db()
    
    users = conn.execute("""
        SELECT id, username, phone, telegram_username, telegram_id, created_at
        FROM users
        ORDER BY created_at DESC
    """).fetchall()
    
    conn.close()
    
    result = []
    for user in users:
        result.append({
            'id': user['id'],
            'username': user['username'],
            'phone': user['phone'],
            'telegram_username': user['telegram_username'],
            'telegram_id': user['telegram_id'],
            'created_at': user['created_at']
        })
    
    return jsonify({'users': result})

@app.route('/api/admin/tokens')
@admin_required
def api_admin_tokens():
    """Список активных токенов"""
    conn = get_db()
    
    tokens = conn.execute("""
        SELECT token, user_id, client_id, created_at, expires_at
        FROM sso_tokens
        WHERE datetime(expires_at) > datetime('now')
        ORDER BY created_at DESC
        LIMIT 100
    """).fetchall()
    
    conn.close()
    
    result = []
    for token in tokens:
        result.append({
            'token': token['token'],
            'user_id': token['user_id'],
            'client_id': token['client_id'],
            'created_at': token['created_at'],
            'expires_at': token['expires_at']
        })
    
    return jsonify({'tokens': result})

@app.route('/api/admin/tokens/<token>', methods=['DELETE'])
@admin_required
def api_admin_revoke_token(token):
    """Отзыв токена"""
    conn = get_db()
    conn.execute('DELETE FROM sso_tokens WHERE token = ?', (token,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ==================== END ADMIN PANEL ROUTES ====================

if __name__ == '__main__':
    # Для локальной разработки на localhost
    # В продакшене используйте WSGI сервер (gunicorn, uwsgi)
    # Порт 5066 - уникальный для dreamID SSO
    app.run(debug=True, host='0.0.0.0', port=5066)

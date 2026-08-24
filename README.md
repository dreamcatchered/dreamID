# dreamID

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat&logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

A self-hosted SSO (Single Sign-On) authentication server. Integrate it into any of your own web services for unified login — one account, one session across all your apps.

OAuth2-compatible (Authorization Code Flow). New client apps are registered via the built-in admin panel.

## Features

- OAuth2 authorization flow
- User registration and login
- Client application management
- Persistent sessions with secure tokens
- Admin dashboard with Telegram-based login
- User management: block / unblock users
- Activity logging (`log_activity`) with an admin activity feed
- Avatar support with automatic local caching
- Quick login via Telegram bot links (`/api/quick-login/check/<token>`)
- Projects list API for connected services (`/api/projects/list`)
- Optional URL shortener integration for QR login links (env-configurable)

## Stack

- Python / Flask
- SQLite
- systemd (production, see `auth-sso.service`)

## Setup

```bash
pip install -r requirements.txt
# Create a .env file and set the variables below
python app.py
```

For production there is a systemd unit example in `auth-sso.service`.

## Admin panel

The admin dashboard is served at `/admin` and is protected by DreamID SSO — access is restricted to a single `ADMIN_TELEGRAM_ID`. From the panel you can:

- create OAuth clients and (re)generate their secrets
- view and revoke active tokens
- browse users and the activity feed

Client integration guide: [INTEGRATION.md](INTEGRATION.md).

## Configuration

All secrets are provided via environment variables — nothing sensitive is stored in the repo.

```env
SECRET_KEY=your_secret_key
SMS_API_KEY=your_sms_api_key          # from the @dream_smsbot
ADMIN_TELEGRAM_ID=your_telegram_id    # admin panel access
ADMIN_CLIENT_SECRET=your_admin_secret
URL_SHORTENER_API=                    # optional; used for QR login links
AUTH_BASE_URL=https://auth.dreampartners.online
SMS_BASE_URL=https://sms.dreampartners.online
```

## Contact

Telegram: [@dreamcatch_r](https://t.me/dreamcatch_r)

---

## Русская версия

# dreamID

Самостоятельно разворачиваемый сервер аутентификации SSO (Single Sign-On). Интегрируйте его в любые свои веб-сервисы для единого входа — один аккаунт, одна сессия во всех ваших приложениях.

Совместим с OAuth2 (Authorization Code Flow). Новые клиентские приложения регистрируются через встроенную админ-панель.

## Возможности

- Авторизация по протоколу OAuth2
- Регистрация и вход пользователей
- Управление клиентскими приложениями
- Постоянные сессии с защищёнными токенами
- Админ-панель со входом через Telegram
- Управление пользователями: блокировка / разблокировка
- Логирование активности (`log_activity`) с лентой событий в админке
- Поддержка аватарок с автоматическим локальным кэшированием
- Быстрый вход через ссылки Telegram-бота (`/api/quick-login/check/<token>`)
- API списка проектов для подключённых сервисов (`/api/projects/list`)
- Опциональная интеграция с сократителем ссылок для QR-входа (настраивается через env)

## Стек

- Python / Flask
- SQLite
- systemd (продакшн, см. `auth-sso.service`)

## Установка

```bash
pip install -r requirements.txt
# Создайте файл .env и задайте переменные ниже
python app.py
```

Для продакшна есть пример systemd-юнита в `auth-sso.service`.

## Админ-панель

Админ-панель доступна по адресу `/admin` и защищена через DreamID SSO — доступ ограничен одним `ADMIN_TELEGRAM_ID`. Из панели можно:

- создавать OAuth-клиентов и (пере)генерировать их секреты;
- просматривать и отзывать активные токены;
- смотреть пользователей и ленту активности.

Руководство по интеграции клиентов: [INTEGRATION.md](INTEGRATION.md).

## Конфигурация

Все секреты передаются через переменные окружения — в репозитории ничего чувствительного не хранится.

```env
SECRET_KEY=your_secret_key
SMS_API_KEY=your_sms_api_key          # из бота @dream_smsbot
ADMIN_TELEGRAM_ID=your_telegram_id    # доступ к админ-панели
ADMIN_CLIENT_SECRET=your_admin_secret
URL_SHORTENER_API=                    # опционально; используется для QR-входа
AUTH_BASE_URL=https://auth.dreampartners.online
SMS_BASE_URL=https://sms.dreampartners.online
```

## Контакты

Telegram: [@dreamcatch_r](https://t.me/dreamcatch_r)

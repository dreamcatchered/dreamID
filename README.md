# dreamID

A self-hosted SSO (Single Sign-On) authentication server. Integrate it into any of your own web services for unified login — one account, one session across all your apps.

OAuth2-compatible. Easy to register new client apps with a single script.

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
- Simple client registration scripts

## Stack

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat&logo=sqlite&logoColor=white)

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
# Set SECRET_KEY in .env
python app.py
```

For production there is a systemd unit example in `auth-sso.service`.

Admin panel setup is described in [AUTH_ADMIN_SETUP.md](AUTH_ADMIN_SETUP.md), client integration in [INTEGRATION.md](INTEGRATION.md).

## Registering a client app

```bash
python register_admin_bot_client.py
python register_cloud_client.py
python register_pay_client.py   # set PAY_ADMIN_CLIENT_SECRET or let it generate one
```

## Configuration

All secrets are provided via environment variables — nothing sensitive is stored in the repo.

```env
SECRET_KEY=your_secret_key
SMS_API_KEY=your_sms_api_key          # from the @dream_smsbot
ADMIN_TELEGRAM_ID=your_telegram_id    # admin panel access
ADMIN_CLIENT_SECRET=your_admin_secret
URL_SHORTENER_API=                    # optional; used for QR login links
CLOUD_CLIENT_SECRET=                  # for update_cloud_redirect.py
AUTH_BASE_URL=https://auth.dreampartners.online
SMS_BASE_URL=https://sms.dreampartners.online
```

## Contact

Telegram: [@dreamcatch_r](https://t.me/dreamcatch_r)

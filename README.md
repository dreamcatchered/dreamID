# dreamID

A self-hosted SSO (Single Sign-On) authentication server. Integrate it into any of your own web services for unified login — one account, one session across all your apps.

OAuth2-compatible. Easy to register new client apps with a single script.

## Features

- OAuth2 authorization flow
- User registration and login
- Client application management
- Persistent sessions with secure tokens
- Admin dashboard
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

## Registering a client app

```bash
python register_admin_bot_client.py
python register_cloud_client.py
```

## Configuration

```env
SECRET_KEY=your_secret_key
ADMIN_TELEGRAM_ID=your_telegram_id
ADMIN_CLIENT_SECRET=your_admin_secret
```

## Contact

Telegram: [@dreamcatch_r](https://t.me/dreamcatch_r)

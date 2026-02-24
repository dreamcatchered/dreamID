# Руководство по интеграции dreamID (SSO)

Этот документ описывает процесс интеграции единой системы авторизации (SSO) **dreamID** в сторонние веб-сайты и приложения.

Система использует стандартный протокол **OAuth 2.0 (Authorization Code Flow)**.

---

## 1. Регистрация клиента

Перед началом работы необходимо зарегистрировать ваше приложение в системе dreamID и получить:
*   `client_id` (Идентификатор клиента)
*   `client_secret` (Секретный ключ - хранить только на сервере!)
*   Добавить `redirect_uri` (URL, куда вернется пользователь после входа)

> Для регистрации обратитесь к администратору dreamID.

---

## 2. Схема авторизации

Процесс входа состоит из 4 шагов:

1.  **Редирект**: Вы перенаправляете пользователя на страницу входа dreamID.
2.  **Вход**: Пользователь вводит телефон/пароль (или SMS код) на сервере dreamID.
3.  **Код**: dreamID возвращает пользователя на ваш сайт с временным `code`.
4.  **Токен**: Ваш сервер обменивает `code` на `access_token` и получает данные пользователя.

---

## 3. Детальное описание API

Базовый URL: `https://auth.dreampartners.online` (или `http://localhost:5066` для разработки)

### Шаг 1: Инициализация входа (Frontend)

Перенаправьте браузер пользователя по адресу:

```
GET /sso
```

**Параметры URL:**

| Параметр | Обязательно | Описание |
| :--- | :--- | :--- |
| `client_id` | Да | Ваш ID клиента |
| `redirect_uri` | Да | URL на вашем сайте, куда вернется пользователь |
| `state` | Нет | Случайная строка для защиты от CSRF (рекомендуется) |

**Пример ссылки:**
```text
https://auth.dreampartners.online/sso?client_id=my_site&redirect_uri=https://mysite.com/callback&state=xyz123
```

### Шаг 2: Обработка возврата (Backend)

После успешного входа пользователь будет перенаправлен на ваш `redirect_uri`:

```text
https://mysite.com/callback?code=AUTH_CODE_HERE&state=xyz123
```

Ваш сервер должен извлечь параметр `code`.

### Шаг 3: Обмен кода на токен (Backend)

Сделайте POST-запрос с вашего сервера на сервер dreamID, чтобы получить токен доступа.

**Endpoint:**
```
POST /api/sso/token
```

**Тело запроса (JSON):**
```json
{
  "code": "AUTH_CODE_HERE",
  "client_id": "your_client_id",
  "client_secret": "your_client_secret"
}
```

**Ответ (Успех 200 OK):**
```json
{
  "access_token": "TOKEN_STRING...",
  "token_type": "Bearer",
  "expires_in": 2592000
}
```

### Шаг 4: Получение данных пользователя (Backend)

Используя полученный токен, запросите профиль пользователя.

**Endpoint:**
```
GET /api/sso/user
```

**Заголовки:**
```text
Authorization: Bearer TOKEN_STRING...
```

**Ответ (Успех 200 OK):**
```json
{
  "id": 123,
  "username": "UserLogin",
  "phone": "+79991234567"
}
```

---

## 4. Примеры кода

### Python (Flask)

```python
import requests
from flask import Flask, redirect, request, session

app = Flask(__name__)
AUTH_URL = "https://auth.dreampartners.online"
CLIENT_ID = "my_app"
CLIENT_SECRET = "secret_key"
REDIRECT_URI = "http://localhost:5000/callback"

@app.route('/login')
def login():
    # Шаг 1: Редирект на SSO
    return redirect(f"{AUTH_URL}/sso?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}")

@app.route('/callback')
def callback():
    code = request.args.get('code')
    
    # Шаг 3: Обмен кода на токен
    token_resp = requests.post(f"{AUTH_URL}/api/sso/token", json={
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }).json()
    
    if 'error' in token_resp:
        return f"Ошибка входа: {token_resp['error']}"
        
    access_token = token_resp['access_token']
    
    # Шаг 4: Получение данных
    user_resp = requests.get(f"{AUTH_URL}/api/sso/user", headers={
        "Authorization": f"Bearer {access_token}"
    }).json()
    
    # Создаем локальную сессию
    session['user'] = user_resp
    return f"Привет, {user_resp['username']}!"
```

### JavaScript (Node.js / Express)

```javascript
const express = require('express');
const axios = require('axios');
const app = express();

const AUTH_URL = "https://auth.dreampartners.online";
const CLIENT_ID = "my_app";
const CLIENT_SECRET = "secret_key";
const REDIRECT_URI = "http://localhost:3000/callback";

app.get('/login', (req, res) => {
    res.redirect(`${AUTH_URL}/sso?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}`);
});

app.get('/callback', async (req, res) => {
    const { code } = req.query;
    
    try {
        // Обмен кода на токен
        const tokenRes = await axios.post(`${AUTH_URL}/api/sso/token`, {
            code,
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET
        });
        
        const { access_token } = tokenRes.data;
        
        // Получение данных
        const userRes = await axios.get(`${AUTH_URL}/api/sso/user`, {
            headers: { Authorization: `Bearer ${access_token}` }
        });
        
        res.send(`Привет, ${userRes.data.username}!`);
        
    } catch (error) {
        res.status(500).send('Ошибка авторизации');
    }
});
```


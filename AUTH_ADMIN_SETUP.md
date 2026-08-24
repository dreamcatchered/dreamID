# 🔐 DreamID Admin Panel - Инструкция

Админ-панель для управления OAuth клиентами, пользователями и токенами DreamID SSO.

## 🌐 Доступ

**URL:** `https://auth.dreampartners.online/admin`  
**Авторизация:** Через DreamID (только для Telegram ID: <ADMIN_TELEGRAM_ID>)

## ✨ Возможности

### 📊 Статистика
- Всего пользователей
- OAuth клиентов
- Активных токенов
- Авторизаций за 24 часа

### 🔑 Управление OAuth клиентами
- ➕ Создание новых клиентов
- 🔑 Просмотр Client Secret
- 🔄 Перегенерация Client Secret
- 🗑️ Удаление клиентов
- 📋 Просмотр Redirect URIs

### 👥 Управление пользователями
- Просмотр всех зарегистрированных пользователей
- Информация о Telegram привязках
- Контактные данные

### 🎫 Управление токенами
- Просмотр активных токенов
- Отзыв токенов
- Мониторинг истечения

## 🚀 Установка

### 1. Клиент уже зарегистрирован

Клиент `auth_admin` уже создан в базе данных:
- **Client ID:** `auth_admin`
- **Client Secret:** `[REDACTED]`
- **Redirect URI:** `https://auth.dreampartners.online/admin/auth/callback`

### 2. Файлы созданы

```
/home/dream/projects/auth/
├── app.py                              # Обновлен с админ-роутами
├── templates/
│   ├── auth_admin_login.html          # Страница входа
│   └── auth_admin_dashboard.html      # Панель управления
└── dreamid.db                         # База данных (клиент зарегистрирован)
```

### 3. Загрузите на сервер

```bash
# Загрузите обновленные файлы
scp app.py dream@server:/home/dream/projects/auth/
scp templates/auth_admin_*.html dream@server:/home/dream/projects/auth/templates/
scp dreamid.db dream@server:/home/dream/projects/auth/

# Перезапустите auth сервис
sudo systemctl restart auth
```

## 📋 Типичные задачи

### Создать нового OAuth клиента

1. Откройте `https://auth.dreampartners.online/admin`
2. Вкладка "🔑 OAuth Клиенты"
3. Нажмите "+ Создать клиента"
4. Заполните:
   - **Client ID** - уникальный идентификатор (например: `my_app`)
   - **Client Secret** - будет сгенерирован автоматически
   - **Название** - отображаемое имя приложения
   - **Redirect URIs** - по одному на строку
5. Нажмите "Создать"
6. Скопируйте Client Secret (он больше не будет показан в открытом виде)

### Перегенерировать Client Secret

1. Найдите клиента в списке
2. Нажмите 🔄 (Перегенерация)
3. Подтвердите действие
4. Скопируйте новый Client Secret
5. Обновите Client Secret в приложении

### Посмотреть Client Secret

1. Найдите клиента в списке
2. Нажмите 🔑 Secret
3. Скопируйте через кнопку "📋 Копировать"

### Отозвать токен

1. Вкладка "🎫 Токены"
2. Найдите токен
3. Нажмите "🗑️ Отозвать"
4. Подтвердите действие

## 🔒 Безопасность

- ✅ Авторизация только через DreamID SSO
- ✅ Проверка Telegram ID (<ADMIN_TELEGRAM_ID>)
- ✅ Все через HTTPS
- ✅ Сессии с автоматическим истечением
- ✅ Client Secrets скрыты по умолчанию

## 🛠️ Управление

```bash
# Статус auth сервиса
sudo systemctl status auth

# Логи
sudo journalctl -u auth -f

# Перезапуск
sudo systemctl restart auth
```

## 🎯 Архитектура

```
auth.dreampartners.online/admin (HTTPS)
    ↓
nginx (порт 443)
    ↓
Flask Auth App (порт 5066)
    ↓
dreamid.db (SQLite)
```

## 📚 API Endpoints

Все API endpoints защищены авторизацией:

- `GET /api/admin/stats` - Статистика
- `GET /api/admin/clients` - Список клиентов
- `POST /api/admin/clients` - Создать клиента
- `DELETE /api/admin/clients/{id}` - Удалить клиента
- `POST /api/admin/clients/{id}/regenerate-secret` - Перегенерировать secret
- `GET /api/admin/users` - Список пользователей
- `GET /api/admin/tokens` - Активные токены
- `DELETE /api/admin/tokens/{token}` - Отозвать токен

## ✅ Готово!

Теперь вы можете управлять всеми OAuth клиентами и пользователями DreamID через удобный веб-интерфейс! 🎉

**Доступ:** `https://auth.dreampartners.online/admin`

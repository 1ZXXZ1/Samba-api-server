---

## ds_auth.py — CLI утилита для управления аутентификацией

### Команды верхнего уровня

| Команда | Описание |
|---------|----------|
| `login` | Войти по логину/паролю, получить JWT |
| `refresh` | Обновить JWT-токен |
| `whoami` | Информация о текущем пользователе |
| `status` | Проверить подключение к API |
| `quickkey` | Быстрое создание ключа (логин + создать ключ одной командой) |

### user — Управление пользователями

```bash
python3 ds_auth.py user list                                    # Список пользователей
python3 ds_auth.py user create operator1 -p secret123 -r operator  # Создать
python3 ds_auth.py user show 2                                  # Показать по ID
python3 ds_auth.py user edit 2 --role admin                     # Изменить роль
python3 ds_auth.py user delete 2 --confirm                      # Деактивировать
```

### key — Управление API-ключами

```bash
python3 ds_auth.py key list                                     # Список ключей
python3 ds_auth.py key create --user-id 1 -n "my-key" -r operator  # Создать
python3 ds_auth.py key show 3                                   # Детали ключа
python3 ds_auth.py key edit 3 --role admin                      # Изменить роль
python3 ds_auth.py key delete 3 --confirm                       # Деактивировать
python3 ds_auth.py key rotate 3                                 # Ротация ключа
```

### role — Управление ролями

```bash
python3 ds_auth.py role list                                    # Список ролей
python3 ds_auth.py role show admin                              # Детали + все права
python3 ds_auth.py role create dns-admin -p dns.zonecreate,dns.zonedelete  # Создать
python3 ds_auth.py role edit dns-admin --add-permissions dns.recordcreate   # Добавить права
python3 ds_auth.py role edit dns-admin --remove-permissions dns.zonedelete  # Убрать права
python3 ds_auth.py role delete dns-admin --confirm              # Удалить
```

### perms — Управление правами

```bash
python3 ds_auth.py perms list                                   # Все 140+ прав
python3 ds_auth.py perms list -c dns                            # Только DNS-права
python3 ds_auth.py perms list -s user                           # Поиск "user"
python3 ds_auth.py perms assign -r operator -p user.create,user.delete  # Назначить
python3 ds_auth.py perms revoke -r operator -p user.delete      # Отозвать
python3 ds_auth.py perms diff admin operator                    # Сравнить роли
```

### audit — Журнал аудита

```bash
python3 ds_auth.py audit list                                   # Все записи
python3 ds_auth.py audit list --user-id 1                       # По пользователю
python3 ds_auth.py audit list --action create                   # По действию
```

### Типичный сценарий первого запуска

```bash
# 1. Логин + сохранение токена
python3 ds_auth.py login admin YOUR_PASSWORD --save

# 2. Создать пользователя
python3 ds_auth.py user create dev1 -p secret -r operator

# 3. Создать API-ключ для пользователя
python3 ds_auth.py key create --user-id 2 -n "dev-key" -r operator --expires-days 90

# 4. Использовать полученный ключ
export SAMBA_API_KEY=sak_полученный_ключ
python3 cli.py user list
```

### Или одной командой (quickkey)

```bash
python3 ds_auth.py quickkey admin YOUR_PASSWORD --key-name "my-key" --role operator
```
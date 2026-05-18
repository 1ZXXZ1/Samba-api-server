# Samba AD DC Management API Server

Промышленный REST API-сервер для удалённого управления Samba AD DC через `samba-tool`. Предоставляет полный доступ ко всем административным операциям через JSON API.

## Возможности

- **Полное покрытие samba-tool**: все команды доступны через REST API
- **Аутентификация по API-ключу**: защита эндпоинтов через заголовок `X-API-Key`
- **Изолированное выполнение**: `ProcessPoolExecutor` для потокобезопасного вызова samba-tool
- **Фоновые задачи**: длительные операции (репликация, бекап) возвращают task_id для отслеживания
- **OpenAPI/Swagger**: автоматическая документация на `/docs`
- **CLI-клиент**: полноценный командный интерфейс на Click
- **Автоматическая совместимость JSON**: автоматический откат `--json` → `--output-format=json` → текстовый вывод при несовместимости версий samba-tool

## Домены API

| Домен | Префикс | Описание |
|-------|---------|----------|
| Users | `/api/v1/users` | Управление пользователями |
| Groups | `/api/v1/groups` | Управление группами |
| Computers | `/api/v1/computers` | Управление компьютерами |
| Contacts | `/api/v1/contacts` | Управление контактами |
| OUs | `/api/v1/ous` | Организационные подразделения |
| Domain | `/api/v1/domain` | Управление доменом, доверия, бекап |
| DNS | `/api/v1/dns` | Управление DNS-зонами и записями |
| Sites | `/api/v1/sites` | Сайты и подсети |
| FSMO | `/api/v1/fsmo` | Просмотр/перехват FSMO-ролей |
| DRS | `/api/v1/drs` | Репликация |
| GPO | `/api/v1/gpo` | Групповые политики |
| Schema | `/api/v1/schema` | Схема AD |
| Delegation | `/api/v1/delegation` | Делегирование |
| Service Accounts | `/api/v1/service-accounts` | Сервисные учётные записи |
| Auth Policies | `/api/v1/auth` | Silos и политики аутентификации |
| Misc | `/api/v1/misc` | dbcheck, ntacl, testparm, SPN и др. |

## Быстрый старт

### 1. Установка зависимостей

```bash
pip install -r requirements.txt
```

### 2. Настройка

```bash
cp .env.example .env
# Отредактируйте .env - обязательно задайте SAMBA_API_KEY
```

### 3. Запуск

```bash
# Автозапуск (создаёт venv, генерирует ключ, запускает на 127.0.0.1:8099)
chmod +x run.sh
./run.sh

# Или вручную
export SAMBA_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
uvicorn app.main:app --host 127.0.0.1 --port 8099
```

### 4. Проверка

```bash
# Health check (без аутентификации)
curl http://127.0.0.1:8099/health

# Пример API-запроса
curl -H "X-API-Key: YOUR_KEY" "http://127.0.0.1:8099/api/v1/domain/info?ip_address=127.0.0.1"
curl -H "X-API-Key: YOUR_KEY" http://127.0.0.1:8099/api/v1/users
```

### 5. Документация

Откройте http://127.0.0.1:8099/docs в браузере для Swagger UI.

## CLI-клиент

### Важно: порядок аргумента `--api-key`

Флаг `--api-key` является опцией **корневой** команды и должен указываться **ДО** подкоманды:

```bash
# ПРАВИЛЬНО:
python cli.py --api-key KEY user list
python cli.py --api-key KEY domain info

# НЕВЕРНО (click не распознает --api-key после подкоманды):
python cli.py user list --api-key KEY
```

### Рекомендуемый способ: переменная окружения или .env

Чтобы не указывать `--api-key` при каждом вызове, используйте один из способов:

```bash
# Способ 1: переменная окружения
export SAMBA_API_KEY=your-key
python cli.py user list
python cli.py group list

# Способ 2: файл .env в текущей директории
# Создайте файл .env со строкой:
# SAMBA_API_KEY=your-key
# SAMBA_API_SERVER=http://127.0.0.1:8099
python cli.py user list  # .env загружается автоматически
```

### Примеры команд

```bash
python cli.py user list
python cli.py user create jsmith --given-name John --surname Smith
python cli.py user show jsmith
python cli.py group list
python cli.py domain info --ip-address 127.0.0.1
python cli.py dns zones list --server dc1.example.com
python cli.py fsmo show
python cli.py drs showrepl
python cli.py gpo list
python cli.py misc testparm
```

## Совместимость версий samba-tool

API-сервер автоматически адаптируется к установленной версии `samba-tool`. Поддерживаются три уровня совместимости JSON-вывода:

| Флаг | Версия Samba | Описание |
|------|-------------|----------|
| `--json` | 4.7+ | Прямой JSON-вывод |
| `--output-format=json` | 4.9+ | Альтернативный формат JSON |
| Без флага | Любая | Текстовый вывод |

### Режимы SAMBA_JSON_MODE

Переменная `SAMBA_JSON_MODE` управляет стратегией JSON-вывода:

| Значение | Поведение |
|----------|-----------|
| `auto` (по умолчанию) | Сначала пробует `--json`, при ошибке — `--output-format=json`, затем — без флага |
| `force_json` | Всегда использовать `--json`, без отката |
| `force_output_format` | Всегда использовать `--output-format=json` вместо `--json` |
| `text` | Никогда не добавлять JSON-флаги, всегда возвращать текст |

Пример настройки для старых версий Samba:

```bash
# Для Samba < 4.7, где --json не поддерживается:
export SAMBA_JSON_MODE=text

# Для Samba 4.9+, предпочитаем --output-format:
export SAMBA_JSON_MODE=force_output_format
```

### Команды без поддержки `-H` (LDAP URL)

Некоторые команды `samba-tool` не поддерживают флаг `-H` (LDAP URL), потому что используют другие протоколы (CLDAP, RPC, прямое чтение ldb). Сервер автоматически пропускает `-H` для этих команд:

- `domain info`, `domain level`, `domain join`, `domain leave`, `domain provision`, `domain backup`, `domain trust`
- `dns serverinfo`, `dns zonelist`, `dns query`, `dns add`, `dns delete`, `dns update`, и др.
- `drs showrepl`, `drs bind`, `drs options`, `drs kcc`, `drs replicate`
- `gpo listall`
- `dbcheck`, `ntacl get/set/sysvolreset`, `testparm`, `time`, `processes`, `forest info`

### Команды без поддержки `-U` (учётные данные)

Некоторые диагностические команды не требуют аутентификации и не поддерживают флаг `-U`. Сервер автоматически пропускает `-U` для этих команд:

- `testparm`, `processes`, `time`, `domain info`, `domain level`

### Удалённые эндпоинты (не поддерживаются samba-tool 4.16+)

Следующие эндпоинты были удалены, так как соответствующие подкоманды отсутствуют в samba-tool:

- `GET /api/v1/domain/tombstones` — нет подкоманды листинга; только `expunge` (деструктивная)
- `GET /api/v1/delegation/` — нет подкоманды `list`; только `show` для конкретной учётной записи
- `GET /api/v1/misc/forest/info` — нет подкоманды `forest info`; используйте LDAP или `domain info`
- `GET /api/v1/misc/visualize` — нет подкоманды `drs visualize` в данной версии

## Docker

```bash
# Сборка
docker build -t samba-api-server .

# Запуск
docker run -d \
  -p 8099:8099 \
  -e SAMBA_API_KEY=your-secret-key \
  -v /etc/samba:/etc/samba:ro \
  -v /var/lib/samba:/var/lib/samba:ro \
  --name samba-api \
  samba-api-server
```

**Важно**: Для операций, требующих root (dbcheck, sysvolreset), контейнер должен работать с соответствующими привилегиями.

## Тестирование

```bash
pip install pytest httpx
pytest test_api.py -v

# С детальным логированием
pytest test_api.py -v --log-cli-level=DEBUG
```

## Переменные окружения

| Переменная | По умолчанию | Описание |
|------------|-------------|----------|
| `SAMBA_API_KEY` | (обязательная) | API-ключ для аутентификации |
| `SAMBA_API_HOST` | `127.0.0.1` | Адрес привязки |
| `SAMBA_API_PORT` | `8099` | Порт сервера |
| `SAMBA_TOOL_PATH` | `samba-tool` | Путь к samba-tool |
| `SAMBA_SMB_CONF` | `/etc/samba/smb.conf` | Путь к smb.conf |
| `SAMBA_SERVER` | `localhost` | Адрес сервера Samba |
| `SAMBA_LDAP_URL` | (пусто) | URL LDAP для удалённого доступа |
| `SAMBA_WORKER_POOL_SIZE` | `4` | Размер пула воркеров |
| `SAMBA_LOG_LEVEL` | `INFO` | Уровень логирования |
| `SAMBA_CREDENTIALS_USER` | (пусто) | Имя пользователя для удалённого доступа |
| `SAMBA_CREDENTIALS_PASSWORD` | (пусто) | Пароль для удалённого доступа |
| `SAMBA_USE_KERBEROS` | `false` | Использовать Kerberos |
| `SAMBA_JSON_MODE` | `auto` | Режим совместимости JSON (auto/force_json/force_output_format/text) |

## Архитектура

```
Запрос → API Key Auth → Router → Executor → ProcessPoolExecutor → samba-tool → JSON ответ
                                                                    ↕
                                                         Worker Pool (лимит 4)
                                                                    ↕
                                              JSON fallback: --json → --output-format → text
```

- **ProcessPoolExecutor**: изолирует вызовы samba-tool в отдельных процессах (не потокобезопасен)
- **API Key**: постоянная времени проверка через `secrets.compare_digest`
- **Task Manager**: in-memory хранение статусов фоновых задач
- **JSON Fallback**: автоматический откат при несовместимости версий (SAMBA_JSON_MODE=auto)
- **Debug логирование**: при `SAMBA_LOG_LEVEL=DEBUG` выводит полную команду и stdout/stderr

## Безопасность

- Все эндпоинты (кроме /health, /docs) требуют API-ключ
- Операции join/leave домена требуют флаг `force: true`
- Длительные операции выполняются асинхронно с возвратом task_id
- API-ключ проверяется с защитой от timing-атак

## Формат ошибок

Все ошибки возвращаются в стандартизированном JSON:

```json
{
  "status": "error",
  "message": "описание ошибки",
  "details": "дополнительная информация (опционально)"
}
```

HTTP-коды: 400 (неверный запрос), 401 (нет ключа), 403 (нет прав), 404 (не найдено), 409 (конфликт), 500 (ошибка сервера), 504 (таймаут).

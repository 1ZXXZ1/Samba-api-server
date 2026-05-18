# Групповые политики, gpupdate, ADMC, GPUI

## Установка инструментов
```bash
# apt-get install admc                  # Консоль управления AD
# apt-get install gpui                  # Редактор политик
# apt-get install gpupdate              # Применение политик на клиенте
# apt-get install alt-gpui-admx         # Административные шаблоны
```

## Включение применения конфигурации
На клиенте Linux:
```bash
# При вводе в домен:
# system-auth write ad test.alt host01 test Administrator --gpo

# Или вручную включить gpupdate
# systemctl enable --now gpupdate
```

## samba-tool gpo
```bash
samba-tool gpo listall                  # Все GPO
samba-tool gpo listcontainers <GUID>    # Контейнеры GPO
samba-tool gpo getlink <DN>             # GPO привязанные к контейнеру
```

## gpupdate (на клиенте)
```bash
# gpupdate                              # Применить все политики
```

## ADMC (GUI)
- Управление объектами домена: пользователи, группы, компьютеры, OU
- Управление GPO: создание, привязка, редактирование
- FSMO роли
- Делегирование

## GPUI (GUI)
- Редактирование параметров GPO
- Административные шаблоны для Linux

## GPResult
- Аналитический отчёт о применённых GPO

## Расширение ГП
Поддерживаемые категории:
- Конфигурация компьютера / пользователя
- Административные шаблоны
- Скрипты (запуск/завершение)
- Переменные среды
- Сетевые параметры
- Безопасность

## SysVol ACL
```bash
samba-tool ntacl sysvolcheck            # Проверка
samba-tool ntacl sysvolreset            # Сброс
```

## Решение проблем GPO
```bash
# Проверить применение
$ gpresult                              # Отчёт

# Очистить кэш SSSD GPO
# sssctl cache-remove

# Логи
$ ls /var/log/gpupdate/
```

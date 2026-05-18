# NTP, chrony, синхронизация времени

## Установка и настройка
```bash
# apt-get install chrony

# Режим сервера (для DC)
# control chrony server

# Настроить пул
# sed -i -r 's/^(pool.*)/#\1\npool ru.pool.ntp.org iburst/' /etc/chrony.conf

# Или вручную в /etc/chrony.conf:
# server 0.ru.pool.ntp.org iburst
# server 1.ru.pool.ntp.org iburst
# pool ru.pool.ntp.org iburst

# Запуск
# systemctl enable --now chronyd

# Статус
# systemctl status chronyd
# chronyc tracking
# chronyc sources -v
```

## Схема NTP
```
Внешние NTP → PDC Emulator DC → Другие DC → Клиенты
```
- PDC Emulator: синхронизируется с внешними серверами
- Другие DC: синхронизируются с PDC Emulator
- Клиенты: синхронизируются с любым DC

## Если PDC недоступен
Установить одинаковые NTP-серверы на всех DC.
Передать роль PDC другому DC:
```bash
# samba-tool fsmo transfer --role=pdc -UAdministrator
```

## Важно
- Kerberos: макс. отклонение 5 минут
- При превышении: доступ запрещён
- Параметр iburst: ускоряет начальную синхронизацию

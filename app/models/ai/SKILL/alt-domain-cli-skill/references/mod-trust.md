# Трасты (доверительные отношения)

## Настройка DNS
Для каждого домена нужна условная пересылка:
```bash
# На DC1 (test.alt) → пересылка в win.alt
# samba-tool dns add dc1 test.alt win.alt A 192.168.0.190 -UAdministrator
# В smb.conf: dns forwarder или условная пересылка

# Или BIND9_DLZ → conditional forwarding
```

## Создание доверия
```bash
# samba-tool domain trust create <other_domain> \
  --type=forest|external \
  --direction=both|in|out \
  --create-location=both \
  -UAdministrator

# Пример: test.alt ↔ win.alt
# На DC test.alt:
# samba-tool domain trust create win.alt --type=forest --direction=both -UAdministrator

# На DC win.alt:
# Аналогичная команда в обратную сторону
```

## Управление пользователями и группами в трасте
```bash
# Добавить пользователя из доверенного домена в локальную группу
# samba-tool group addmembers "Domain Admins" "WIN\user" --object-types=user
```

## Использование на Linux-клиентах
```bash
# Вход как пользователь доверенного домена
$ kinit user@WIN.ALT
# Или: WIN\user

# wbinfo
$ wbinfo --trusted-domains
$ wbinfo --all-domains
$ wbinfo --domain-info win.alt
```

## Удаление доверия
```bash
# samba-tool domain trust delete <other_domain> -UAdministrator
```

## Важно
- Samba <4.21.7: проблемы совместимости с Win Server (обновления 08.07.2025)
- Рекомендуется обновить Samba до ≥4.21.7 или ≥4.22.3
- DNS: каждому домену нужна пересылка к другому
- Для BIND9_DLZ можно использовать conditional forwarding

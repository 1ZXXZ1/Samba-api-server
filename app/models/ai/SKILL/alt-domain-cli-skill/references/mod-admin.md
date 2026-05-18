# Администрирование: FSMO, уровни, сайты, gMSA, пароли

## FSMO роли
```bash
$ samba-tool fsmo show
# Роли: rid, pdc, infrastructure, schema, naming, domaindns, forestdns

# Передача роли
# samba-tool fsmo transfer --role=pdc -UAdministrator

# Захват роли (если DC мёртв)
# samba-tool fsmo seize --role=pdc -UAdministrator
# samba-tool fsmo seize --force --role=pdc
```

## Функциональные уровни
```bash
$ samba-tool domain level show

# Повышение
# samba-tool domain level raise --domain-level=2012_R2 --forest-level=2012_R2
# samba-tool domain level raise --domain-level=2016 --forest-level=2016

# Сначала подготовка
# samba-tool domain functionalprep --function-level=2012_R2
# samba-tool domain schemaupgrade --schema=88
```
Доступные уровни: 2008_R2 (по умолч.), 2012, 2012_R2, 2016
⚠ 2012_R2: сначала развернуть 2008_R2, затем повысить!

## Сайты и подсети
```bash
$ samba-tool sites list
# samba-tool sites create <sitename>
$ samba-tool sites subnet list <sitename>
# samba-tool sites subnet create <subnet> <sitename>
# samba-tool sites subnet remove <subnet>
```

## gMSA (групповые управляемые учётные записи служб)
```bash
# Создать KDS Root Key (если ещё нет)
# Создать gMSA через ADUC/ADMC

# Через adcli:
# adcli create-msa --domain=test.alt

# Получить пароль gMSA:
# samba-tool user getpassword gmsa$ --attributes=virtualClearTextUTF8
```

## Парольные политики
```bash
# Через samba-tool:
$ samba-tool domain passwordsettings show -UAdministrator

# Настроить (пример):
# samba-tool domain passwordsettings set \
  --complexity=default \
  --min-pwd-length=7 \
  --min-pwd-age=1 \
  --max-pwd-age=90 \
  --history-length=24 \
  -UAdministrator
```

## Управление паролями локальных администраторов
Настраивается через GPO: LAPS-подобное управление

## Samba привязка к интерфейсам
```ini
# smb.conf
[global]
    interfaces = lo eth0
    bind interfaces only = yes
```

## DHCP → DNS обновление
Настроить DHCP для обновления DNS-записей:
- На DC: разрешить динамические обновления
- На DHCP: настроить nsupdate / samba_dnsupdate

## LDAPS
```bash
# В smb.conf (по умолчанию включено)
tls enabled = yes
# Порт 636 (LDAPS), 3269 (GC SSL)
```

## NTP на DC
См. mod-ntp.md

## DFS (распределённая файловая система)
```bash
# Создать DFS корень через samba-tool или ADMC
# Настроить ссылки на файловые серверы
```

## Samba файловый сервер (в режиме member)
См. mod-samba-file.md

## Журналирование Samba
```ini
# smb.conf
[global]
    log level = 3
    log file = /var/log/samba/log.%m
    max log size = 5000
```

## UID/GID планирование (IDMapping)
```ini
# Winbind idmap_ad
idmap config * : backend = tdb
idmap config * : range = 10000-19999
idmap config TEST : backend = ad
idmap config TEST : range = 20000-999999

# Winbind idmap_rid
idmap config * : backend = tdb
idmap config * : range = 10000-19999
idmap config TEST : backend = rid
idmap config TEST : range = 20000-999999

# SSSD auto
# ldap_id_mapping = True (автоматический)
# ldap_id_mapping = False (из AD, нужен RFC2307)
```

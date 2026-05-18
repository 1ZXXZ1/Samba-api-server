
name:alt-domain-cli-skill
description: справочник команд CLI для администрирования Альт Домен
-  
# ALT Domain 11.1 CLI — AI Skill
## Мета
- Версия: 11.1 (март 2026)
- ОС: Альт Сервер / Альт Домен
## Правило загрузки (token-efficient)
AI загружает ТОЛЬКО нужный модуль по запросу пользователя.
Индекс модулей → файл `index.md`
Команды → файлы `mod-*.md`

## Триггеры активации
- Команды ALT Linux, Альт Домен, Альт Сервер
- samba-tool, alteratorctl, system-auth в контексте ALT
- sssd/winbind в контексте ALT Domain
- GPO/gpupdate в контексте ALT
- Kerberos/LDAP/SMB в контексте Альт Домен
- Разворачивание домена, контроллер домена, репликация
- RODC, FSMO, трасты, сайты, подсети

## Ограничения
- Только CLI, GUI не описан
- Команды для root помечены `#`, пользовательские `$`
- Realm ВСЕГДА в верхнем регистре для Kerberos
- Пароль ≥7 символов, ≥3 группы символов (A-Z, a-z, 0-9, спец)
- Имя хоста ≤15 символов (sAMAccountName)
- Доменное имя ≥2 компонента через точку
- НЕ использовать .local (иначе отключить avahi-daemon)
- Samba <4.21.7 несовместима с Win Server обновлениями от 08.07.2025

## Быстрые шаблоны

### Создание DC (alteratorctl)
```
# alteratorctl services deploy service-samba-ad \
  --mode=create --realm=TEST.ALT --netBiosName=test \
  --mode.create.adminPassword='Pa$$word' \
  --dnsSettings.dnsBackend=SAMBA_INTERNAL \
  --dnsSettings.forwarders.0=8.8.8.8
# alteratorctl services start service-samba-ad
```

### Создание DC (samba-tool)
```
# samba-tool domain provision \
  --realm=test.alt --domain=test \
  --adminpass='Pa$$word' \
  --dns-backend=SAMBA_INTERNAL \
  --option="dns forwarder=8.8.8.8" \
  --server-role=dc --use-rfc2307
# systemctl enable --now samba
```

### Ввод клиента в домен
```
# apt-get install task-auth-ad-sssd
# system-auth write ad test.alt host01 test Administrator 'Pa$$word'
```

### Проверка домена
```
$ kinit administrator@TEST.ALT
$ host -t SRV _ldap._tcp.test.alt
$ samba-tool domain info 127.0.0.1
```

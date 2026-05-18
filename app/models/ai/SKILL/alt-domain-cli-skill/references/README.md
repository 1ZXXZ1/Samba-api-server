# ALT Domain 11.1 CLI — AI Skill

Оптимизированный справочник команд для администрирования Альт Домен 11.1.
Модульная структура — AI загружает только нужный раздел.

## Структура

| Файл | Описание |
|------|----------|
| skill.md | Мета-информация, триггеры, быстрые шаблоны |
| index.md | Индекс модулей для ленивой загрузки |
| mod-deploy.md | Разворачивание домена, DC, RODC |
| mod-hostname-net.md | Имя хоста, сеть, DNS, resolvconf |
| mod-samba-tool.md | samba-tool — все подкоманды |
| mod-alteratorctl.md | alteratorctl — сервисы, редакции |
| mod-clients.md | Клиенты: SSSD, Winbind, system-auth |
| mod-kerberos.md | Kerberos: kinit, klist, keytab |
| mod-ldap.md | LDAP: ldbsearch, ldapsearch |
| mod-gpo.md | Групповые политики, gpupdate |
| mod-repl.md | Репликация, SysVol, DRS |
| mod-trust.md | Трасты, доверительные отношения |
| mod-dns-bind.md | BIND9_DLZ, DNS-настройки |
| mod-admin.md | FSMO, уровни, сайты, gMSA, пароли |
| mod-backup.md | Резервное копирование, восстановление |
| mod-ports-config.md | Порты, конфигурационные файлы |
| mod-troubleshoot.md | Диагностика, отладка |
| mod-ntp.md | NTP, chrony |
| mod-samba-file.md | Файловый сервер, shares, монтирование |

## Использование

1. Прочитать `index.md` для навигации
2. Загрузить только нужный `mod-*.md` по теме запроса
3. Использовать `skill.md` для быстрых шаблонов и ограничений

## Принцип оптимизации токенов

- Команды в компактном формате без лишних слов
- Все опции в таблицах
- Дублирование исключено: общие параметры в одном месте
- Модули автономны — не требуют перекрёстных ссылок
- AI не загружает весь справочник, только релевантный модуль

# samba-tool — все подкоманды

## Пользователи
```bash
# Добавить
samba-tool user add <user> [password] [opts]
  --surname= --given-name= --initials= --mail-address=
  --must-change-at-next-login --random-password --smartcard-required
  --use-username-as-cn --userou=OU=Users,DC=test,DC=alt
  --company= --department= --description=
  --rfc2307-from-niss --nis-domain= --unix-home= --uid= --uid-number= --gid-number= --gecos= --login-shell=

# Удалить / отключить / включить
samba-tool user delete <user>
samba-tool user disable <user>|--filter <f>
samba-tool user enable <user>|--filter <f>

# Список / показать
samba-tool user list [--full-dn] [-b BASE_DN] [--hide-expired] [--hide-disabled]
samba-tool user show <user>

# Пароль
samba-tool user password  # текущий пользователь
samba-tool user setpassword <user> --newpassword=PASS [--must-change-at-next-login] [--random-password]
samba-tool user getpassword <user> --attributes=virtualClearTextUTF8,virtualCryptSHA512 [--decrypt-samba-gpg]

# Срок действия
samba-tool user setexpiry <user> --days=N|--noexpiry

# Группы пользователя
samba-tool user getgroups <user>
samba-tool user setprimarygroup <user> <group>

# Разблокировка
samba-tool user unlock <user>|--filter <f>

# Перемещение / переименование
samba-tool user move <user> <container>
samba-tool user rename <user>

# Удалённое выполнение: -H ldap://<DC>
```

## Группы
```bash
samba-tool group add <group> [--groupou= --group-scope=Domain|Global|Universal --group-type=Security|Distribution --description= --mail-address= --notes= --gid-number= --nis-domain= --special]
samba-tool group delete <group>
samba-tool group list [--full-dn] [-b BASE_DN]
samba-tool group listmembers <group>
samba-tool group show <group>
samba-tool group stats
samba-tool group move <group> <container>
samba-tool group rename <group>
samba-tool group addmembers <group> <members> [--member-dn= --object-types=user|group|computer|serviceaccount|contact|all --member-base=]
samba-tool group removemembers <group> <members> [--member-dn= --object-types=]
samba-tool group addunixattrs <group> <gidnumber>
samba-tool group edit <group>
```

## Компьютеры
```bash
samba-tool computer <subcommand>  # add, delete, list, show, move, rename, edit
```

## OU (Organizational Units)
```bash
samba-tool ou <subcommand>  # add, delete, list, show, move, rename, edit
```

## DNS
```bash
samba-tool dns add <server> <zone> <name> <A|AAAA|PTR|CNAME|NS|MX|SRV|TXT> <data> -U<user>
samba-tool dns delete <server> <zone> <name> <TYPE> <data> -U<user>
samba-tool dns update <server> <zone> <name> <TYPE> <old> <new> -U<user>
samba-tool dns query <server> <zone> <name> <A|AAAA|PTR|CNAME|NS|MX|SOA|SRV|TXT|ALL> -U<user>
samba-tool dns cleanup <server> <hostname>
samba-tool dns zonecreate <server> <zone> [--client-version=w2k|dotnet|longhorn] -U<user>
samba-tool dns zonedelete <server> <zone> -U<user>
samba-tool dns zoneinfo <server> <zone> -U<user>
samba-tool dns zonelist <server> [--primary|--secondary|--cache|--auto|--reverse|--ds|--non-ds] -U<user>
samba-tool dns zoneoptions <server> <zone> [--aging=0|1] [--norefreshinterval=N] [--refreshinterval=N] [--mark-old-records-static=YYYY-MM-DD] [--mark-records-static-regex=REGEXP] [-n] -U<user>
samba-tool dns serverinfo <server> [--client-version=w2k|dotnet|longhorn] -U<user>
samba-tool dns roothints <server> [<name>] -U<user>
```

## Репликация (DRS)
```bash
samba-tool drs replicate <dest> <source> <NC> -U<user>
samba-tool drs showrepl [-U<user>]
samba-tool drs showrepl --summary -U<user>
```

## FSMO
```bash
samba-tool fsmo show
samba-tool fsmo transfer --role=<role> [-UAdministrator]
samba-tool fsmo seize --role=<role> [-UAdministrator]
samba-tool fsmo seize --force --role=<role>
# Роли: rid, pdc, infrastructure, schema, naming, domaindns, forestdns, all
```

## GPO
```bash
samba-tool gpo listall
samba-tool gpo listcontainers <GPO-GUID>
samba-tool gpo getlink <DN>
```

## Уровни и схема
```bash
samba-tool domain level show
samba-tool domain level raise --domain-level=<LEVEL> --forest-level=<LEVEL>
samba-tool domain schemaupgrade --schema=<SCHEMA>
samba-tool domain functionalprep --function-level=<LEVEL>
```

## Бэкап домена
```bash
samba-tool domain backup online --targetdir=<dir> --server=<DC> -UAdministrator
samba-tool domain backup offline --targetdir=<dir>
samba-tool domain backup rename <new-netbios> <new-realm> --server=<DC> --targetdir=<dir> [--no-secrets] -UAdministrator
samba-tool domain backup restore --backup-file=<tar> --newservername=<name> --targetdir=<dir> [--site=<site>]
```

## Сайты и подсети
```bash
samba-tool sites list
samba-tool sites create <sitename>
samba-tool sites subnet list <sitename>
samba-tool sites subnet create <subnet> <sitename>
samba-tool sites subnet remove <subnet>
```

## RODC
```bash
samba-tool rodc preload <SID|DN|account>+ [--server= --file= --ignore-errors]
```

## SPN
```bash
samba-tool spn add <SPN> <sAMAccountName>
```

## Keytab
```bash
samba-tool domain exportkeytab <file>.keytab --principal=<sAMAccountName|SPN>
```

## NTACL (SysVol)
```bash
samba-tool ntacl sysvolcheck
samba-tool ntacl sysvolreset
```

## Прочие
```bash
samba-tool domain info 127.0.0.1
samba-tool domain demote -Uadministrator
samba-tool domain demote --remove-other-dead-server=<name>
samba-tool dbcheck                       # Проверка БД
samba-tool ldapcmp ldap://dc1 ldap://dc2  # Сравнение LDAP
samba-tool time                          # Время сервера
samba-tool processes                     # Процессы
samba-tool delegation                    # Делегирование
samba-tool dsacl                         # DS ACL
samba-tool forest                        # Лес
samba-tool schema                        # Схема
samba-tool contact                       # Контакты
samba-tool visualize                     # Граф состояния
```

## LDAP Compare — детальнее
```bash
samba-tool ldapcmp ldap://dc1 ldap://dc2 -U<user>
  --scope=DOMAIN|CONFIGURATION|SCHEMA|ALL
```

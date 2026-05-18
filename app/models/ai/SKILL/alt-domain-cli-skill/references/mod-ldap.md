# LDAP: ldbsearch, ldbmodify, ldapsearch, LDIF

## ldbsearch
```bash
# Поиск по sam.ldb
$ ldbsearch -H /var/lib/samba/private/sam.ldb [filter] [attrs]
$ ldbsearch -H /var/lib/samba/private/sam.ldb '(invocationId=*)' --cross-ncs objectguid
$ ldbsearch -H /var/lib/samba/private/sam.ldb -s base -b <DN> <attrs>

# Область поиска: -s base|one|sub|children
```

## ldbmodify
```bash
$ ldbmodify -H /var/lib/samba/private/sam.ldb <file.ldif> \
  --option="dsdb:schema update allowed"=true
```

## ldapsearch
```bash
$ ldapsearch [params] <filter> <attrs>
```
| Параметр | Описание |
|----------|----------|
| -H URI | LDAP сервер (ldap://dc1.test.alt) |
| -D binddn | Bind DN |
| -b basedn | Base DN |
| -x | Простая аутентификация |
| -W | Запросить пароль |
| -w passwd | Пароль |
| -L / -LL / -LLL | LDIF без комментариев |
| -s base\|one\|sub\|children | Область поиска |
| -f file | Фильтры из файла |
| -Y mech | SASL механизм |
| -Z / -ZZ | StartTLS |
| -E [!]ext | Расширения поиска |
| -e [!]ext | Расширения общие |

Пример:
```bash
$ ldapsearch -H ldap://dc1.test.alt -D "CN=Administrator,CN=Users,DC=test,DC=alt" -W -b "DC=test,DC=alt" "(objectClass=user)" sAMAccountName
```

## LDAPS (LDAP over SSL)
По умолчанию tls enabled = yes в smb.conf → LDAPS на порту 636
```bash
$ ldapsearch -H ldaps://dc1.test.alt -D "CN=Administrator,CN=Users,DC=test,DC=alt" -W -b "DC=test,DC=alt"
```

## tdbbackup
```bash
# tdbbackup -s .bak /var/lib/samba/private/idmap.ldb
```

## Важные DN
```
DC=test,DC=alt                                    # Корень домена
CN=Users,DC=test,DC=alt                           # Пользователи
CN=Computers,DC=test,DC=alt                       # Компьютеры
OU=Domain Controllers,DC=test,DC=alt              # Контроллеры домена
CN=System,DC=test,DC=alt                          # Системный контейнер
CN=MicrosoftDNS,CN=System,DC=test,DC=alt          # DNS записи
CN=Sites,CN=Configuration,DC=test,DC=alt          # Сайты AD
CN=Subnets,CN=Sites,CN=Configuration,DC=test,DC=alt  # Подсети
```

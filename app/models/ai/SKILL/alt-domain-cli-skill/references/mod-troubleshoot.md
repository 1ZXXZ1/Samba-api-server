# Диагностика, отладка, решение проблем

## Диагностический инструмент (ADT)
```bash
# apt-get install diag-domain-controller
# diag-domain-controller  # Запуск диагностики
```

## Отладка Samba
```bash
# Интерактивный режим
# samba -i

# С указанным конфигом
# samba -s /etc/samba/smb.conf

# Debug уровень
# smb.conf: log level = 1-10
$ testparm -v                           # Все параметры

# Логи
$ ls /var/log/samba/
$ journalctl -u samba -f               # Журнал службы
```

## Отладка DNS
```bash
$ host -t A dc1.test.alt
$ host -t SRV _ldap._tcp.test.alt
$ host -t SRV _kerberos._udp.test.alt
$ ss -tulpn | grep ":53"               # Кто занял порт 53
$ samba-tool dns query 127.0.0.1 test.alt @ ALL -UAdministrator
```

## Отладка Kerberos
```bash
$ kinit administrator@TEST.ALT
$ klist
$ klist -ke /etc/krb5.keytab
```

## Отладка репликации
```bash
# samba-tool drs showrepl -UAdministrator
# samba-tool ldapcmp ldap://dc1 ldap://dc2 -UAdministrator
```

## Отладка SSSD
```bash
$ sssctl domain-status test.alt
$ sssctl user-checks ivanov
$ sssctl config-check
$ sssctl debug-level 9
$ sssctl logs-fetch /tmp/ssslogs.tar.gz
$ sssctl cache-remove
# systemctl restart sssd
```

## Отладка Winbind
```bash
$ wbinfo -p                            # Пинг winbindd
$ wbinfo -t                            # Проверка доверия
$ wbinfo -P                            # Пинг DC
$ wbinfo -u                            # Пользователи
$ wbinfo -g                            # Группы
$ wbinfo -i ivanov                     # Инфо пользователя
$ net ads testjoin                     # Проверка членства
$ net ads info                         # Информация о домене
```

## Отладка LDAP
```bash
$ ldbsearch -H /var/lib/samba/private/sam.ldb '(objectClass=user)' sAMAccountName
$ samba-tool dbcheck                   # Проверка БД
```

## Отладка GPO
```bash
$ gpresult                             # Отчёт о применении
$ samba-tool gpo listall
$ samba-tool ntacl sysvolcheck
```

## Типичные проблемы

### Samba не запускается
```bash
# Перезагрузить сервер
# reboot
# Проверить логи: journalctl -u samba
```

### Bind не запускается (DLZ конфликт)
```bash
# Закомментировать /etc/bind/local.conf
# Добавить override: Environment="LDB_MODULES_DISABLE_DEEPBIND=1"
# systemctl daemon-reload && systemctl restart bind
```

### Время расходится
```bash
# systemctl status chronyd
# chronyc tracking
```

### DNS запросы не проходят
```bash
# Проверить resolv.conf: nameserver 127.0.0.1
# Проверить порт 53: ss -tulpn | grep ":53"
# systemctl restart samba
```

### Пользователь не может войти
```bash
$ kinit user@TEST.ALT
$ wbinfo -a 'TEST\user%password'
$ sssctl user-checks user
$ getent passwd user
```

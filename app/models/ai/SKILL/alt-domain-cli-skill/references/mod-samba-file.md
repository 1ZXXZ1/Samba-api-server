# Samba файловый сервер, shares, Usershares, монтирование

## Файловый сервер в режиме member
```bash
# apt-get install task-samba-dc  # или samba
# Ввод в домен (см. mod-clients.md)
```

## smb.conf — файловый сервер
```ini
[global]
    security = ads
    realm = TEST.ALT
    workgroup = TEST
    winbind use default domain = yes
    winbind offline logon = yes
    winbind refresh tickets = yes
    kerberos method = secrets and keytab

    idmap config * : backend = tdb
    idmap config * : range = 10000-19999
    idmap config TEST : backend = rid
    idmap config TEST : range = 20000-999999

[data]
    path = /srv/data
    browseable = yes
    read only = no
    valid users = @"TEST\Domain Users"
```

## Usershares (пользовательские ресурсы)
```ini
[global]
    usershare path = /var/lib/samba/usershares
    usershare max shares = 100
    usershare allow guests = no
    usershare owner only = no
```
```bash
# mkdir -p /var/lib/samba/usershares
# chmod 1770 /var/lib/samba/usershares
# chown root:sambashare /var/lib/samba/usershares

# Создать share пользователем:
$ net usershare add sharename /path/to/dir "Comment" everyone:F
$ net usershare delete sharename
$ net usershare list
$ net usershare info sharename
```

## Монтирование SMB ресурсов
```bash
# apt-get install cifs-utils

# Монтирование
# mount -t cifs //dc1/data /mnt/data -o username=ivanov,domain=TEST

# Через Kerberos
# mount -t cifs //dc1/data /mnt/data -o sec=krb5,multiuser,cruid=%(UID)

# /etc/fstab
//dc1/data /mnt/data cifs sec=krb5,multiuser,cruid=%(UID),_netdev 0 0
```

## smbclient
```bash
$ smbclient -L localhost -Uadministrator   # Список шар
$ smbclient -L <server> -U<user>          # Шары сервера
$ smbclient //dc1/data -U ivanov          # Подключение
```

## smbstatus
```bash
$ smbstatus                                # Текущие подключения
$ smbstatus -b                             # Краткий вывод
$ smbstatus -u <user>                      # Подключения пользователя
```

## Журналирование
```ini
[global]
    log level = 3
    log file = /var/log/samba/log.%m
    max log size = 5000
```

## Проверка конфигурации
```bash
$ testparm
```

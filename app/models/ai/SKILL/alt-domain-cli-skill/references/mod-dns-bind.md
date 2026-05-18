# BIND9_DLZ, named.conf, DNS-настройки

## Установка BIND
```bash
# apt-get install bind bind-utils
```

## Настройка для Альт Домен
```bash
# Отключить chroot
# control bind-chroot disabled

# KRB5RCACHETYPE
# grep -q KRB5RCACHETYPE /etc/sysconfig/bind || \
  echo 'KRB5RCACHETYPE="none"' >> /etc/sysconfig/bind

# Подключить DLZ
# grep -q 'bind-dns' /etc/bind/named.conf || \
  echo 'include "/var/lib/samba/bind-dns/named.conf";' >> /etc/bind/named.conf

# Остановить bind до создания домена
# systemctl stop bind
```

## /etc/bind/options.conf
```
options {
    version "unknown";
    directory "/etc/bind/zone";
    dump-file "/var/run/named/named_dump.db";
    statistics-file "/var/run/named/named.stats";
    pid-file none;
    tkey-gssapi-keytab "/var/lib/samba/bind-dns/dns.keytab";
    minimal-responses yes;
    listen-on { 127.0.0.1; 192.168.0.132; };
    listen-on-v6 { ::1; };
    allow-query { localnets; 192.168.0.0/24; };
    allow-recursion { localnets; 192.168.0.0/24; };
    forward first;
    forwarders { 8.8.8.8; };
};
logging {
    category lame-servers {null;};
};
```

## Конфликт зоны
Если при установке задано FQDN, автосоздаётся зона → конфликт:
```bash
# Решение: закомментировать всё в /etc/bind/local.conf
# Или удалить файл
```

## systemd override для bind
```bash
# mkdir -p /etc/systemd/system/bind.service.d
# cat << EOF > /etc/systemd/system/bind.service.d/override.conf
[Service]
Environment="LDB_MODULES_DISABLE_DEEPBIND=1"
EOF
# systemctl daemon-reload
```

## Миграция DNS бэкенда
```bash
# samba_upgradedns --dns-backend=BIND9_DLZ    # → BIND9_DLZ
# samba_upgradedns --dns-backend=SAMBA_INTERNAL # → SAMBA_INTERNAL
```

## nsupdate — динамическое обновление DNS
```bash
$ nsupdate [-dDi] [-g|-o|-y keyname:secret|-k keyfile] [-v] [-4|-6] [file]
```
Интерактивные команды: server, local, zone, class, ttl, key, gsstsig, realm,
prereq nxdomain/yxdomain/nxrrset/yxrrset, update delete/add, show, send, answer, debug

## rndc
```bash
# rndc status
# rndc reload
# rndc stop
```

## Утилиты BIND
- named-checkconf — проверка синтаксиса
- named-checkzone — проверка зон
- dig — запросы DNS
- host — информация об именах
- nslookup — DNS запросы
- nsupdate — динамические обновления

## Запуск
```bash
# systemctl enable --now samba
# systemctl enable --now bind
```

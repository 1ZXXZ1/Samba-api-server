# Имя хоста, сеть, DNS, resolvconf

## hostnamectl
```bash
# hostnamectl set-hostname dc1.test.alt  # FQDN для DC
$ hostnamectl                             # Текущее состояние
$ hostname -s                             # Короткое имя
```
⚠ Имя ≤15 символов! Имя домена ≥2 компонента через точку!

## Сетевые настройки
```bash
# Консоль: /etc/net/ifaces/<iface>/resolv.conf
nameserver 127.0.0.1
nameserver 8.8.8.8
search test.alt

# Обновить DNS
# resolvconf -u

# Проверить /etc/resolv.conf
nameserver 127.0.0.1
search test.alt
```

## resolvconf.conf
```
# /etc/resolvconf.conf
name_servers=127.0.0.1
```
```bash
# resolvconf -u
```

## systemd-resolved конфликт
```ini
# /etc/systemd/resolved.conf
DNSStubListener=no
```
```bash
# systemctl restart systemd-resolved
```

## DNS-проверки
```bash
$ host -t A dc1.test.alt
$ host -t SRV _ldap._tcp.test.alt
$ host -t SRV _kerberos._udp.test.alt
$ host -t PTR 192.168.0.132
$ nslookup dc1.test.alt
$ ss -tulpn | grep ":53"
```

## Важно
- До развёртывания: внешний DNS допустим временно
- После развёртывания: только 127.0.0.1 или свой IP
- НЕ использовать .local (иначе avahi-daemon отключить)
- На вторичном DC указать первичный в DNS-серверах

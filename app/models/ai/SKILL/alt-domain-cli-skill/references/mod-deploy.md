# Разворачивание домена / DC / RODC

## Предварительные шаги
```bash
# NTP
# apt-get install chrony
# control chrony server
# systemctl enable --now chronyd

# Имя хоста
# hostnamectl set-hostname dc1.test.alt

# DNS → 127.0.0.1
# echo "nameserver 127.0.0.1" > /etc/net/ifaces/enp0s3/resolv.conf
# echo "search test.alt" >> /etc/net/ifaces/enp0s3/resolv.conf
# resolvconf -u

# resolvconf.conf → name_servers=127.0.0.1
# resolvconf -u
```

## Способ 1: alteratorctl (рекомендуется)
```bash
# apt-get install alterator-service-samba-ad

# Создание нового домена
# alteratorctl services deploy service-samba-ad \
  --mode=create \
  --realm=TEST.ALT \
  --netBiosName=test \
  --hostNetBiosName=dc1 \
  --mode.create.adminPassword='Pa$$word' \
  --dnsSettings.dnsBackend=SAMBA_INTERNAL \
  --dnsSettings.forwarders.0=8.8.8.8 \
  --functionalLevel=2008_R2 \
  --backendStore=tdb \
  --use-rfc2307=true \
  --siteName=Default-First-Site-Name

# Запуск
# alteratorctl services start service-samba-ad

# Присоединение доп. DC
# alteratorctl services deploy service-samba-ad \
  --mode=join \
  --realm=TEST.ALT \
  --mode.join.adminLogin=Administrator \
  --mode.join.adminPassword='Pa$$word' \
  --mode.join.ipAddressDc=192.168.0.132 \
  --mode.join.serverRole=dc

# Присоединение RODC
# alteratorctl services deploy service-samba-ad \
  --mode=join \
  --mode.join.serverRole=rodc \
  --mode.join.adminLogin=Administrator \
  --mode.join.adminPassword='Pa$$word' \
  --mode.join.ipAddressDc=192.168.0.132
```

### deploy — все параметры
| Параметр | Значения | По умолч. |
|----------|----------|-----------|
| --backendStore | tdb, mdb | tdb |
| --backendStore.mdb.backendStoreSize | 1-... ГБ | 4 |
| --dnsSettings.dnsBackend | SAMBA_INTERNAL, BIND9_DLZ | SAMBA_INTERNAL |
| --dnsSettings.dnsBackend.BIND9_DLZ.bindSettings.allowQuery.N | IP подсеть | — |
| --dnsSettings.dnsBackend.BIND9_DLZ.bindSettings.allowRecursion.N | IP подсеть | — |
| --dnsSettings.dnsBackend.BIND9_DLZ.bindSettings.dnssecValidation | true, false | false |
| --dnsSettings.dnsBackend.BIND9_DLZ.bindSettings.listenOn.N | IP | any |
| --dnsSettings.dnsBackend.BIND9_DLZ.bindSettings.listenOnV6.N | IPv6 | none |
| --dnsSettings.forwarders.N | IP DNS | — |
| --functionalLevel | 2008_R2, 2016 | 2008_R2 |
| --hostNetBiosName | Имя DC | hostname |
| --mode | create, join | join |
| --mode.create.adminPassword | Пароль | интерактив |
| --mode.join.adminLogin | Логин админа | — |
| --mode.join.adminPassword | Пароль | интерактив |
| --mode.join.ipAddressDc | IP существующего DC | — |
| --mode.join.serverRole | dc, rodc | dc |
| --netBiosName | NetBIOS домена | из FQDN |
| --realm | Kerberos realm / DNS домен | из FQDN |
| --siteName | AD сайт | Default-First-Site-Name |
| --use-rfc2307 | true, false | false |

Опции: -f/--force-deploy, -y/--yes, --no-default

### undeploy
```bash
# alteratorctl services undeploy service-samba-ad \
  --adminLogin=Administrator \
  --adminPassword='Pa$$word' \
  --forceUndeploy=true \
  --resetToDefaults=true \
  --saveCurrentConfig=true
```
Опции: -y/--yes, --no-default

## Способ 2: samba-tool
```bash
# Остановка конфликтов
# for s in smb nmb krb5kdc slapd bind; do systemctl disable $s; systemctl stop $s; done

# Установка
# apt-get install task-samba-dc          # Heimdal
# apt-get install task-samba-dc-mitkrb5  # MIT

# Heimdal: отключить KEYRING
# control krb5-conf-ccache default

# Сброс старой конфигурации
# rm -f /etc/samba/smb.conf
# rm -rf /var/lib/samba /var/cache/samba
# mkdir -p /var/lib/samba/sysvol

# Интерактивное создание
# samba-tool domain provision

# Пакетное создание (SAMBA_INTERNAL)
# samba-tool domain provision \
  --realm=test.alt --domain=test \
  --adminpass='Pa$$word' \
  --dns-backend=SAMBA_INTERNAL \
  --option="dns forwarder=8.8.8.8" \
  --server-role=dc --use-rfc2307

# Пакетное создание (BIND9_DLZ)
# samba-tool domain provision \
  --realm=test.alt --domain=test \
  --adminpass='Pa$$word' \
  --dns-backend=BIND9_DLZ \
  --server-role=dc --use-rfc2307

# Уровень 2016
# samba-tool domain provision \
  --realm=test.alt --domain=test \
  --adminpass='Pa$$word' \
  --dns-backend=SAMBA_INTERNAL \
  --option="dns forwarder=8.8.8.8" \
  --option="ad dc functional level = 2016" \
  --server-role=dc --function-level=2016

# Запуск
# systemctl enable --now samba
# systemctl enable --now bind  # для BIND9_DLZ

# Копирование krb5.conf
# cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
```

### samba-tool domain provision — опции
| Опция | Описание |
|-------|----------|
| --interactive | Интерактивный режим |
| --domain=DOMAIN | NetBIOS имя |
| --domain-guid=GUID | GUID домена |
| --domain-sid=SID | SID домена |
| --host-name=HOSTNAME | Имя DC |
| --host-ip=IP | IPv4 |
| --host-ip6=IP6 | IPv6 |
| --adminpass=PASS | Пароль администратора |
| --krbtgtpass=PASS | Пароль krbtgt |
| --dns-backend=BACKEND | SAMBA_INTERNAL/BIND9_DLZ/NONE |
| --dnspass=PASS | Пароль DNS |
| --server-role=ROLE | dc/member/standalone |
| --function-level=LEVEL | 2000/2003/2008/2008_R2/2016 |
| --base-schema=VER | Версия схемы (по умолч. 2019) |
| --use-rfc2307 | UID/GID в LDAP |
| --machinepass=PASS | Пароль компьютера |
| --plaintext-secrets | Без шифрования секретов |
| --realm=REALM | Kerberos realm |
| --option=OPT | Параметр smb.conf |
| -s FILE | Файл конфигурации |
| -d LEVEL | Debug 1-10 |

## Присоединение DC (samba-tool)
```bash
# samba-tool domain join test.alt DC \
  -UAdministrator --realm=TEST.ALT \
  --dns-backend=SAMBA_INTERNAL \
  --option="dns forwarder=8.8.8.8" \
  --option='idmap_ldb:use rfc2307 = yes'

# RODC
# samba-tool domain join test.alt RODC \
  -UAdministrator --realm=TEST.ALT \
  --dns-backend=SAMBA_INTERNAL

# С привязкой к интерфейсам
--option="interfaces= lo eth0" --option="bind interfaces only=yes"

# В конкретный сайт
--site=SiteName
```

## Проверка работоспособности
```bash
$ kinit administrator@TEST.ALT
$ host -t SRV _ldap._tcp.test.alt
$ host -t SRV _kerberos._udp.test.alt
$ host -t A dc1.test.alt
$ samba-tool domain info 127.0.0.1
$ smbclient -L localhost -Uadministrator
```

## Удаление DC
```bash
# samba-tool domain demote -Uadministrator
# Удалить мёртвый DC
# samba-tool domain demote --remove-other-dead-server=DC3
```

## Системные требования DC
- RAM: ≥4 ГБ (тест 2 ГБ), см. таблицу масштабирования
- Диск: ≥10 ГБ + логи + бэкапы, SSD обязательно
- CPU: 4 vCPU на сотни пользователей, формула: cores = Uc / (r × t), r=2, t=300
- Порты: 53,88,123,135,137-139,389,445,464,636,3268,3269,49152-65535
- Масштаб: до 700K пользователей, 700K компьютеров, 100K групп, 1.5M объектов

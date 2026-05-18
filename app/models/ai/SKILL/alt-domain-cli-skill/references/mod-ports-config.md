# Порты, конфигурационные файлы, smb.conf

## Порты DC
| Служба | Порт | Протокол |
|--------|------|----------|
| DNS | 53 | TCP+UDP |
| Kerberos | 88 | TCP+UDP |
| NTP | 123 | UDP |
| RPC Endpoint Mapper | 135 | TCP |
| NetBIOS Name | 137 | UDP |
| NetBIOS Datagram | 138 | UDP |
| NetBIOS Session | 139 | TCP |
| LDAP | 389 | TCP+UDP |
| SMB | 445 | TCP |
| Kerberos kadmin | 464 | TCP+UDP |
| LDAPS | 636 | TCP |
| Global Catalog | 3268 | TCP |
| GC SSL | 3269 | TCP |
| Dynamic RPC | 49152-65535 | TCP |

## Конфигурационные файлы
| Путь | Назначение |
|------|------------|
| /etc/samba/smb.conf | Основной конфиг Samba |
| /var/lib/samba/private/krb5.conf | Samba-генерированный krb5 |
| /var/lib/samba/private/kdc.conf | KDC конфигурация |
| /var/lib/samba/private/sam.ldb | БД AD Samba |
| /var/lib/samba/private/idmap.ldb | ID mapping БД |
| /var/lib/samba/private/secrets.ldb | Секреты |
| /var/lib/samba/sysvol | SysVol (GPO, скрипты) |
| /var/lib/samba/bind-dns/named.conf | BIND DLZ интеграция |
| /var/lib/samba/bind-dns/dns.keytab | DNS keytab |
| /etc/krb5.conf | Kerberos клиент |
| /etc/sssd/sssd.conf | SSSD |
| /etc/resolv.conf | DNS резолвер |
| /etc/resolvconf.conf | resolvconf |
| /etc/net/ifaces/<iface>/resolv.conf | DNS интерфейса |
| /etc/chrony.conf | NTP |
| /etc/bind/named.conf | BIND главный |
| /etc/bind/options.conf | BIND параметры |
| /etc/bind/local.conf | BIND локальные зоны |
| /etc/bind/rndc.conf | BIND управление |
| /etc/sysconfig/bind | BIND sysconfig |
| /etc/nsswitch.conf | Name Service Switch |
| /etc/pam.d/system-auth | PAM |
| /etc/pam.d/system-auth-common | PAM общий |
| /etc/openldap/ldap.conf | OpenLDAP |
| /etc/systemd/resolved.conf | systemd-resolved |
| /var/log/samba/ | Логи Samba |
| /var/lib/sss/db/ | SSSD кэш БД |
| /var/lib/sss/gpo_cache/ | SSSD GPO кэш |
| /var/lib/samba/winbindd_cache.tdb | Winbind кэш |
| /var/lib/samba/winbindd_idmap.tdb | Winbind IDMAP |
| /var/lib/samba/gencache.tdb | Winbind общий кэш |
| /var/lib/alterator/service/samba-ad/status.json | Статус Samba AD |

## smb.conf — ключевые параметры
```ini
[global]
    # DC
    dns forwarder = 8.8.8.8
    netbios name = DC1
    realm = TEST.ALT
    server role = active directory domain controller
    workgroup = TEST
    idmap_ldb:use rfc2307 = yes
    ad dc functional level = 2008_R2

    # Интерфейсы
    interfaces = lo eth0
    bind interfaces only = yes

    # DNS scavenging
    dns zone scavenging = yes

    # Отключить внутренний DNS
    server services = s3fs, rpc, nbt, wrepl, ldap, cldap, kdc, drepl, winbindd, ntp_signd, kcc, dnsupdate
    server services = -dns

    # Логирование
    log level = 3
    log file = /var/log/samba/log.%m
    max log size = 5000

[sysvol]
    path = /var/lib/samba/sysvol
    read only = No

[netlogon]
    path = /var/lib/samba/sysvol/test.alt/scripts
    read only = No
```

## smb.conf — член домена (файловый сервер)
```ini
[global]
    security = ads
    realm = TEST.ALT
    workgroup = TEST
    winbind use default domain = yes
    winbind offline logon = yes
    winbind refresh tickets = yes
    winbind enum users = no
    winbind enum groups = no
    kerberos method = secrets and keytab

    idmap config * : backend = tdb
    idmap config * : range = 10000-19999
    idmap config TEST : backend = rid
    idmap config TEST : range = 20000-999999
```

## sssd.conf — ключевые параметры
```ini
[sssd]
domains = test.alt
services = nss, pam

[domain/test.alt]
id_provider = ad
auth_provider = ad
chpass_provider = ad
access_provider = ad
default_shell = /bin/bash
fallback_homedir = /home/%d/%u
cache_credentials = true
ad_gpo_ignore_unreadable = true
ad_gpo_access_control = permissive|enforcing|disabled
ad_update_samba_machine_account_password = true
dyndns_update = true
dyndns_update_ptr = true
dyndns_refresh_interval = 86400
dyndns_ttl = 3600
dyndns_iface = eth0
dyndns_force_tcp = false
dyndns_auth = GSS-TSIG
dyndns_server = dc1.test.alt
ldap_id_mapping = True|False
ldap_schema = ad
```

## Проверка smb.conf
```bash
$ testparm
$ testparm -s --section-name=global --parameter-name="ad dc functional level"
```

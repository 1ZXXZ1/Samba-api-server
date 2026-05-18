# Репликация, SysVol, DRS

## Настройка репликации
```bash
# Репликация раздела
# samba-tool drs replicate dc2.test.alt dc1.test.alt DC=test,DC=alt -UAdministrator

# Репликация всех разделов
# samba-tool drs replicate dc2 dc1 DC=ForestDnsZones,DC=test,DC=alt -UAdministrator
# samba-tool drs replicate dc2 dc1 DC=DomainDnsZones,DC=test,DC=alt -UAdministrator
# samba-tool drs replicate dc2 dc1 CN=Configuration,DC=test,DC=alt -UAdministrator
```

## Проверка репликации
```bash
# samba-tool drs showrepl -UAdministrator
# samba-tool drs showrepl --summary -UAdministrator
# samba-tool ldapcmp ldap://dc1 ldap://dc2 -UAdministrator
```

## Двунаправленная репликация SysVol

### Способ 1: rsync + unison
```bash
# apt-get install rsync unison
```
Настройка unison профиля /root/.unison/default.prf:
```ini
root = /var/lib/samba/sysvol
root = ssh://dc2.test.alt//var/lib/samba/sysvol
path = test.alt
force = /var/lib/samba/sysvol
batch = true
```

```bash
# unison -auto -batch
```

### Способ 2: rsync + osync
```bash
# apt-get install rsync osync
```
Настройка /etc/osync/sync.conf:
```ini
INITIATOR_SYNC_DIR="/var/lib/samba/sysvol"
TARGET_SYNC_DIR="ssh://root@dc2.test.alt//var/lib/samba/sysvol"
```

```bash
# osync.sh /etc/osync/sync.conf
```

### Способ 3: rsync (односторонняя)
```bash
# rsync -avz --delete /var/lib/samba/sysvol/ dc2:/var/lib/samba/sysvol/
```

## Логи синхронизации
```bash
$ cat /var/log/sysvol-sync.log
```

## Важно
- SysVol = /var/lib/samba/sysvol
- ACL должны совпадать → samba-tool ntacl sysvolreset
- После изменений GPO дать время на репликацию

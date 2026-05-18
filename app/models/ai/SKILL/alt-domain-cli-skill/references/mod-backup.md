# Резервное копирование и восстановление

## Онлайн-бэкап
```bash
# samba-tool domain backup online \
  --targetdir=/backup \
  --server=dc1.test.alt \
  -UAdministrator
```

## Оффлайн-бэкап
```bash
# systemctl stop samba
# samba-tool domain backup offline --targetdir=/backup
# systemctl start samba
```

## Бэкап с переименованием
```bash
# samba-tool domain backup rename <new-netbios> <new-realm> \
  --server=dc1 --targetdir=/backup [--no-secrets] -UAdministrator
```

## Восстановление
```bash
# samba-tool domain backup restore \
  --backup-file=/backup/samba-backup-*.tar \
  --newservername=dc1 \
  --targetdir=/restore \
  [--site=Default-First-Site-Name]
```

## TDB бэкап
```bash
# tdbbackup -s .bak /var/lib/samba/private/idmap.ldb
# tdbbackup -s .bak /var/lib/samba/private/sam.ldb
```

## Восстановление из TDB бэкапа
```bash
# systemctl stop samba
# cp /var/lib/samba/private/idmap.ldb.bak /var/lib/samba/private/idmap.ldb
# systemctl start samba
```

## Ключевые файлы для бэкапа
- /var/lib/samba/private/sam.ldb
- /var/lib/samba/private/idmap.ldb
- /var/lib/samba/private/secrets.ldb
- /var/lib/samba/private/secrets.tdb
- /var/lib/samba/sysvol/
- /etc/samba/smb.conf
- /etc/krb5.conf
- /var/lib/samba/bind-dns/

## Рекомендации
- Минимум 2 DC → автоматическая отказоустойчивость
- Регулярный онлайн-бэкап
- Проверка бэкапа восстановлением на тестовый сервер
- Хранить бэкапы на отдельном носителе

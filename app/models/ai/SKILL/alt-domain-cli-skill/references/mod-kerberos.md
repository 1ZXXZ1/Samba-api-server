# Kerberos: kinit, klist, keytab, krb5.conf, FAST

## Получение тикета
```bash
$ kinit administrator@TEST.ALT          # Realm ВЕРХНИЙ РЕГИСТР!
$ kinit ivanov                          # Без явного realm
$ kinit -k 'HOSTNAME$'                  # Тикет через keytab машины
$ kinit -5 -V -k -t <keytab> <principal> # Через конкретный keytab
```

## Просмотр / удаление
```bash
$ klist                                 # Список тикетов
$ klist -ke <keytab>                    # Записи keytab
$ kdestroy                              # Уничтожить тикеты
```

## krb5.conf
```bash
# Копирование Samba-сгенерированного
# cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
# НЕ создавать симлинк!
```

Пример /etc/krb5.conf:
```ini
[libdefaults]
    default_realm = TEST.ALT
    dns_lookup_realm = false
    dns_lookup_kdc = true
    # Heimdal: отключить KEYRING
    # default_ccache_name = FILE:/tmp/krb5cc_%{uid}

[realms]
    TEST.ALT = {
        kdc = dc1.test.alt
        admin_server = dc1.test.alt
    }

[domain_realm]
    .test.alt = TEST.ALT
    test.alt = TEST.ALT
```

## Heimdal vs MIT
- Heimdal: KDC встроен в Samba, не зависит от /etc/krb5.conf
- MIT: требуется корректный /etc/krb5.conf, нет встроенного KDC
- НЕСОВМЕСТИМЫ между собой!
```bash
# control krb5-conf-ccache default      # Отключить KEYRING для Heimdal
```

## Создание keytab
```bash
# samba-tool domain exportkeytab /etc/krb5.keytab --principal=HOSTNAME$
# samba-tool domain exportkeytab service.keytab --principal=HTTP/web.test.alt
```

## FAST (Kerberos Armoring)
Включает усиленную защиту Kerberos. Настраивается через GPO или smb.conf:
```ini
[global]
    kerberos encryption type = aes256-cts-hmac-sha1-96
```

## Централизованные политики Kerberos
Настраиваются через GPO: Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Kerberos Policy

## Аутентификация сервисов
```bash
# Создать SPN
# samba-tool spn add HTTP/web.test.alt web$

# Экспортировать keytab
# samba-tool domain exportkeytab /etc/web.keytab --principal=HTTP/web.test.alt
```

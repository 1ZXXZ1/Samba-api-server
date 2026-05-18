# Клиенты: SSSD, Winbind, system-auth, adcli, wbinfo, sssctl

## Установка клиентских пакетов
```bash
# SSSD (рекомендуется)
# apt-get install task-auth-ad-sssd

# Winbind
# apt-get install task-auth-ad-winbind
```

## system-auth — ввод в домен
```bash
$ system-auth status             # Текущая схема
$ system-auth list               # Доступные схемы

# Ввод через SSSD (по умолчанию)
# system-auth write ad test.alt host01 test Administrator

# Ввод через Winbind
# system-auth write ad test.alt host01 test Administrator --winbind

# С поддержкой GPO
# system-auth write ad test.alt host01 test Administrator --gpo

# В конкретную OU
# system-auth write ad test.alt host01 test Administrator --createcomputer=OU/SubOU

# NetBIOS имя если >15 символов
--netbiosname=short_hostname

# Совместимость Win2003
--windows2003
```

## Подготовка клиента
```bash
# Имя хоста
# hostnamectl set-hostname host-01.test.alt

# DNS → IP контроллера домена
# echo "nameserver 192.168.0.132" > /etc/net/ifaces/enp0s3/resolv.conf
# echo "search test.alt" >> /etc/net/ifaces/enp0s3/resolv.conf
# resolvconf -u

# Проверка DNS
$ host -t SRV _ldap._tcp.test.alt
$ host -t A dc1.test.alt
```

## Вход доменного пользователя
- GDM/KDM: выбрать «Войти с доменным аккаунтом»
- Консоль: `ivanov` (без домена если winbind use default domain = yes)
- С доменом: `TEST\ivanov` или `ivanov@test.alt`

## Отображение глобальных групп → локальные
```bash
# rolelst                                   # Список маппингов
```

## Удаление клиента из домена
```bash
# system-auth write local                   # Вернуть локальную аутентификацию
# Удалить записи DNS для клиента на DC
```

## Повторная регистрация
```bash
# system-auth write ad test.alt host01 test Administrator
```

## adcli — утилита AD
```bash
$ adcli info <domain>                       # Информация о домене
# adcli join <domain>                       # Ввести машину в домен
# adcli update                              # Обновить пароль маш. аккаунта
$ adcli testjoin                            # Проверить членство
# adcli create-user --domain=<d> <user>     # Создать пользователя
# adcli delete-user --domain=<d> <user>     # Удалить пользователя
# adcli passwd-user --domain=<d> <user>     # Сменить пароль
# adcli create-group --domain=<d> <group>   # Создать группу
# adcli delete-group --domain=<d> <group>   # Удалить группу
# adcli add-member --domain=<d> <group> <member>
# adcli remove-member --domain=<d> <group> <member>
# adcli preset-computer --domain=<d> <comp> # Предсоздать учётку
# adcli reset-computer --domain=<d> <comp>  # Сбросить учётку
# adcli delete-computer --domain=<d> <comp> # Удалить учётку
# adcli show-computer -D <d> <comp>         # Показать атрибуты
# adcli create-msa --domain=<d>             # Создать MSA (gMSA)
```

## wbinfo
```bash
wbinfo -u|--domain-users              # Пользователи домена
wbinfo -g|--domain-groups             # Группы домена
wbinfo -n|--name-to-sid <name>        # Имя → SID
wbinfo -s|--sid-to-name <sid>         # SID → имя
wbinfo -S|--sid-to-uid <sid>          # SID → UID
wbinfo -U|--uid-to-sid <uid>          # UID → SID
wbinfo -Y|--sid-to-gid <sid>          # SID → GID
wbinfo -G|--gid-to-sid <gid>          # GID → SID
wbinfo -i|--user-info <user>          # Информация о пользователе
wbinfo -r|--user-groups <user>        # Группы пользователя
wbinfo -a|--authenticate <user>%<pass> # Аутентификация
wbinfo -K|--krb5auth <user>%<pass>    # Kerberos аутентификация
wbinfo -t|--check-secret              # Проверка доверия
wbinfo -p|--ping                      # Пинг winbindd
wbinfo -P|--ping-dc                   # Пинг DC канала
wbinfo -m|--trusted-domains           # Доверенные домены
wbinfo -D|--domain-info <domain>      # Информация о домене
wbinfo --all-domains                  # Все домены
wbinfo --own-domain                   # Собственный домен
wbinfo --separator                    # Разделитель
wbinfo --online-status [<domain>]     # Статус подключения
wbinfo --dc-info <domain>             # Текущий DC
wbinfo --group-info <group>           # Информация о группе
wbinfo --uid-info <uid>               # UID → информация
wbinfo --gid-info <gid>               # GID → информация
wbinfo --allocate-uid                 # Новый UID
wbinfo --allocate-gid                 # Новый GID
wbinfo -c|--change-secret             # Сменить пароль доверия
wbinfo --set-uid-mapping UID SID      # Маппинг UID↔SID
wbinfo --remove-uid-mapping UID SID
wbinfo --set-gid-mapping GID SID      # Маппинг GID↔SID
wbinfo --remove-gid-mapping GID SID
wbinfo --lookup-sids SID1,SID2...     # Поиск SID
wbinfo -R|--lookup-rids rid1,rid2...  # RID → имена
wbinfo --sid-aliases <sid>            # Псевдонимы SID
wbinfo --sid-to-fullname <sid>        # SID → полное имя
wbinfo --sids-to-unix-ids sid1,sid2... # SID → Unix ID
wbinfo --user-sidinfo <sid>           # Инфо пользователя по SID
wbinfo --user-domgroups <sid>         # Доменные группы пользователя
wbinfo --user-sids <sid>              # SID групп пользователя
wbinfo --dsgetdcname <domain>         # Найти DC
wbinfo --getdcname <domain>           # Имя DC
wbinfo --ccache-save <user>%<pass>    # Сохранить в ccache
wbinfo --domain <domain>              # Указать домен
```

## sssctl
```bash
sssctl domain-list                    # Список доменов
sssctl domain-status <domain>         # Статус домена
sssctl user-checks <user>             # Проверка пользователя
sssctl user-show <user>               # Кэшированный пользователь
sssctl group-show <group>             # Кэшированная группа
sssctl cache-remove                   # Очистить кэш
sssctl cache-expire                   # Инвалидировать кэш
sssctl cache-upgrade                  # Обновить кэш
sssctl cache-index <action>           # Индексы кэша
sssctl config-check                   # Проверка конфигурации
sssctl debug-level [level]            # Уровень отладки
sssctl logs-remove                    # Удалить логи
sssctl logs-fetch <file>              # Архив логов
sssctl analyze                        # Анализ логов
sssctl client-data-backup             # Бэкап данных
sssctl client-data-restore            # Восстановление
sssctl cert-show <cert>               # Сертификат
sssctl cert-map <cert>                # Маппинг сертификата
```

## NSS проверки
```bash
$ getent passwd <user>                 # Пользователь из NSS
$ getent group <group>                 # Группа из NSS
```

## SSSD control
```bash
# control sssd-drop-privileges unprivileged|privileged|default
# control sssd-dyndns-update enabled|disabled|default
# control sssd-dyndns-update-ptr enabled|disabled|default
# control sssd-dyndns-refresh-interval <INTERVAL>|disabled
# control sssd-dyndns-ttl <TTL>|disabled
```

## Обновление пароля маш. аккаунта
```bash
# adcli update                          # Через adcli
# net ads changetrustpw                 # Через net
```

## Аутентификация на DC
Для входа доменных пользователей на сам DC:
```bash
# apt-get install task-auth-ad-sssd
# system-auth write ad test.alt dc1 test Administrator
```

## PAM
```bash
# control pam_canonicalize_user enabled  # Канонизация имён
```
Файлы: /etc/pam.d/system-auth, /etc/pam.d/system-auth-common

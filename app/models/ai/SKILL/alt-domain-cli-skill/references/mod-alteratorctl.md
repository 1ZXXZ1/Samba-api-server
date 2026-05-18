# alteratorctl — сервисы, редакции, компоненты

## Редакции
```bash
$ alteratorctl editions                    # Список (* = текущая)
$ alteratorctl editions license edition_domain  # Лицензия ALT Домен
# alteratorctl editions set edition_domain  # Переключить на ALT Домен
```
Редакции: edition_domain (Альт Домен), edition_server (Альт Сервер)

## Компоненты
```bash
# alteratorctl components install samba-dc  # Установить samba-dc
```

## services deploy — см. mod-deploy.md

## services undeploy
```bash
# alteratorctl services undeploy service-samba-ad [ОПЦИИ] [ПАРАМЕТРЫ]
```
Опции: -y/--yes, --no-default

| Параметр | Описание |
|----------|----------|
| --adminLogin=LOGIN | Логин админа для понижения |
| --adminPassword=PASS | Пароль админа |
| --forceUndeploy=true\|false | Принудительно (по умолч. false) |
| --resetToDefaults=true\|false | Сбросить конфиги (по умолч. false) |
| --saveCurrentConfig=true\|false | Сохранить конфиги (по умолч. false) |

## services start/stop
```bash
# alteratorctl services start service-samba-ad
```

## Справка
```bash
$ alteratorctl services deploy service-samba-ad --help
```

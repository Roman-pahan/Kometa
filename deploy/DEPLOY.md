# Развёртывание Quasarex на сервере

Домен: **quasarex.ch**. Регистратор — европейский (Infomaniak, Hostpoint, EuroDNS), не американский.

## 1. Сервер

Подойдёт VPS с 1 CPU / 1 ГБ RAM / Ubuntu 24.04 — сайту этого хватает с запасом.
Провайдеры, принимающие криптовалюту: 1984 Hosting (Исландия), OrangeWebsite (Исландия), Njalla.

```
apt update && apt install -y nodejs npm nginx certbot python3-certbot-nginx
adduser --system --group --home /opt/quasarex quasarex
```

## 2. DNS

В панели регистратора добавьте A-запись:

```
quasarex.ch.      A     <IP сервера>     TTL 300
www.quasarex.ch.  A     <IP сервера>     TTL 300
```

TTL 300 секунд — чтобы при переезде на другой сервер изменения расходились за минуты.

## 3. Код и зависимости

```
rsync -av --exclude node_modules --exclude data ./ root@СЕРВЕР:/opt/quasarex/
cd /opt/quasarex && npm install --omit=dev
chown -R quasarex:quasarex /opt/quasarex
```

## 4. Ключ шифрования фото

Сгенерируйте ключ и впишите его в `deploy/quasarex.service` (строка `UPLOADS_KEY`):

```
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

**Сохраните этот ключ в менеджере паролей.** Без него фото верификаций не расшифровать — ни вам, ни кому-либо ещё.
Если переносите существующие данные, возьмите ключ из локального файла `secret.key`, иначе старые фото не откроются.

## 5. Запуск сервиса

```
cp deploy/quasarex.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now quasarex
systemctl status quasarex
```

Первый запуск создаёт администратора. Чтобы не остался пароль по умолчанию, задайте свой заранее:

```
systemctl stop quasarex
ADMIN_EMAIL=you@mail.com ADMIN_PASSWORD='ваш-пароль' node server.js   # один раз, затем Ctrl+C
systemctl start quasarex
```

## 6. Nginx и HTTPS

```
cp deploy/nginx-quasarex.conf /etc/nginx/sites-available/quasarex
ln -s /etc/nginx/sites-available/quasarex /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
certbot --nginx -d quasarex.ch -d www.quasarex.ch
```

**HTTPS обязателен**: без него браузер не даст доступ к камере, и верификация клиентов работать не будет.
Certbot сам добавит редирект с http на https и продлевает сертификат автоматически.

## 7. После запуска — в админке

1. Сменить пароль администратора (Настройки).
2. Вписать Telegram для клиентов вместо заглушки `your_telegram`.
3. Заполнить SMTP, иначе письма «забыли пароль» не уходят.
4. Нажать «Экспорт ключа» во вкладке Чат и сохранить строку — без неё переписка не читается с другого браузера.
5. Проверить Telegram-уведомления кнопкой «Тестовое уведомление».

## 8. Резервные копии

Ежедневный бэкап базы и загруженных файлов:

```
0 4 * * * tar czf /root/backup-$(date +\%F).tar.gz /opt/quasarex/data
```

Отдельно и в другом месте храните `UPLOADS_KEY` — бэкап без ключа бесполезен для фото.

## Переезд на другой домен

Домен в коде нигде не зашит: ссылки в письмах собираются из адреса, по которому открыт сайт.
Порядок действий: направить A-запись нового домена на тот же IP, выпустить сертификат
(`certbot --nginx -d новый-домен`), поменять `server_name` в конфиге nginx, сообщить адрес клиентам через Telegram-бот.

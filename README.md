# 🇷🇺 THIS README IS IN RUSSIAN

# 🇺🇸 [ENGLISH VERSION → README.en.md](README.en.md)

---

# MikroTik Security Watch

Набор скриптов и Zabbix-шаблон, которые следят не за "жив ли роутер",
а конкретно за **security-событиями** на MikroTik: появился новый
пользователь, включили telnet/ftp, пропало правило drop в фаерволе,
поменялась версия RouterOS — и присылают алерт в Zabbix.

Обычные шаблоны для Zabbix+MikroTik мониторят трафик, CPU, аптайм.
Этот — конкретно про безопасность конфигурации.

---

## Как это работает

1. `run_check.py` подключается к роутеру по API (через `librouteros`)
и снимает "снимок" текущего состояния: пользователи, включённые сервисы,
фаервол, NTP, версия RouterOS.
2. Снимок сравнивается с сохранённым `baseline.json` с прошлого запуска.
3. Найденные различия превращаются в события с уровнем важности
(`info` / `warning` / `high` / `critical`).
4. И состояние, и события отправляются в Zabbix через trapper-протокол
(без установки `zabbix_sender`, чистый Python через `py-zabbix`).
5. Новый снимок сохраняется как baseline для следующего запуска.

Скрипт ничего не решает и не блокирует — только наблюдает и сообщает.

---

## Установка

```bash
git clone <адрес-этого-репозитория>
cd mikrotik-security-watch
pip install -r requirements.txt
```

### 1. Читающий аккаунт на роутере

Не используй основного admin'а — создай отдельного пользователя только
для чтения:

```
/user group add name=zbx-readonly policy=api,read,!write,!policy,!test,!password,!sniff,!sensitive
/user add name=zbx-secwatch group=zbx-readonly password="сложный-пароль"
```

### 2. Импорт Zabbix-шаблона

В Zabbix: **Data collection → Templates → Import** →
`zabbix/template_mikrotik_security_watch.xml`. Затем привяжи шаблон
`MikroTik Security Watch` к хосту, который представляет твой роутер.

### 3. Запуск по расписанию

```bash
python3 run_check.py \
    --router-host 192.168.88.1 \
    --router-user zbx-secwatch \
    --router-password 'сложный-пароль' \
    --zabbix-server 10.0.0.5 \
    --zabbix-host "MikroTik Office"
```

Добавь в cron (например, раз в 5 минут):

```
*/5 * * * * cd /path/to/mikrotik-security-watch && python3 run_check.py --router-host ... --zabbix-server ... --zabbix-host "MikroTik Office" >> secwatch.log 2>&1
```

---

## Что отслеживается

| Событие | Важность |
|---|---|
| Новый пользователь добавлен | high |
| Пользователь удалён | warning |
| У пользователя повышена группа прав | high |
| Отключённый пользователь снова включён | warning |
| Включён telnet / ftp / www | high |
| Изменён разрешённый адрес доступа к сервису | warning |
| Пропало drop-правило в цепочке input | critical |
| Уменьшилось число правил фаервола | warning |
| Отключён NTP-клиент | info |
| Изменилась версия RouterOS | info |

Полный список кодов событий — в `secwatch/baseline.py`.

---

## Тесты

Всё покрыто тестами на фейковом API, реальный роутер не нужен:

```bash
pip install -r requirements-dev.txt
pytest
```

---

## Структура проекта

```
mikrotik-security-watch/
├── secwatch/
│   ├── collector.py   # снимает состояние роутера
│   ├── baseline.py    # сравнивает два снимка, находит события
│   └── send.py        # отправляет метрики в Zabbix
├── run_check.py        # точка входа (запускается по cron)
├── zabbix/
│   └── template_mikrotik_security_watch.xml
├── tests/
└── requirements.txt
```

## Лицензия

MIT — см. `LICENSE`.

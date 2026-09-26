# 🇷🇺 THIS README IS IN RUSSIAN

# 🇺🇸 [ENGLISH VERSION → README.en.md](README.en.md)

---

# MikroTik Security Watch

Скрипт и Zabbix-шаблон для отслеживания security-событий на MikroTik: новый пользователь, включённый telnet/ftp, пропавшее правило firewall, смена версии RouterOS.

Обычные Zabbix-шаблоны для MikroTik следят за трафиком, CPU, аптаймом. Этот следит за безопасностью конфигурации.

---

## Как это работает

1. `run_check.py` подключается к роутеру и снимает текущее состояние: пользователи, включённые сервисы, firewall, NTP, версия RouterOS.
2. Состояние сравнивается с сохранённым `baseline.json` от прошлого запуска.
3. Найденные изменения превращаются в события с уровнем важности: `info`, `warning`, `high` или `critical`.
4. Состояние и события отправляются в Zabbix через trapper-протокол (библиотека `py-zabbix`, без установки `zabbix_sender`).
5. Новое состояние сохраняется как baseline для следующего запуска.

Скрипт только наблюдает и сообщает. Ничего не блокирует и не чинит сам.

---

## Установка

```bash
git clone <адрес репозитория>
cd mikrotik-security-watch
pip install -r requirements.txt
```

### 1. Создай read-only пользователя на роутере

Не используй основного admin. Создай отдельный аккаунт только для чтения:

```
/user group add name=zbx-readonly policy=api,read,!write,!policy,!test,!password,!sniff,!sensitive
/user add name=zbx-secwatch group=zbx-readonly password="сложный-пароль"
```

### 2. Импортируй Zabbix-шаблон

Zabbix: Data collection → Templates → Import → `zabbix/template_mikrotik_security_watch.xml`. Привяжи шаблон `MikroTik Security Watch` к нужному хосту.

### 3. Настрой запуск по расписанию

```bash
python3 run_check.py \
    --router-host 192.168.88.1 \
    --router-user zbx-secwatch \
    --router-password 'сложный-пароль' \
    --zabbix-server 10.0.0.5 \
    --zabbix-host "MikroTik Office"
```

Добавь в cron, например раз в 5 минут:

```
*/5 * * * * cd /path/to/mikrotik-security-watch && python3 run_check.py --router-host ... --zabbix-server ... --zabbix-host "MikroTik Office" >> secwatch.log 2>&1
```

---

## Что отслеживается

| Событие | Важность |
|---|---|
| Новый пользователь | high |
| Пользователь удалён | warning |
| Пользователю подняли права | high |
| Отключённый пользователь снова включён | warning |
| Включён telnet, ftp или www | high |
| Изменён разрешённый адрес доступа к сервису | warning |
| Пропало drop-правило в input | critical |
| Стало меньше правил firewall | warning |
| Отключён NTP | info |
| Сменилась версия RouterOS | info |

Полный список кодов событий смотри в `secwatch/baseline.py`.

---

## Тесты

Тесты работают на фейковом API, реальный роутер не нужен.

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
│   ├── baseline.py    # сравнивает снимки, находит события
│   └── send.py        # отправляет метрики в Zabbix
├── run_check.py        # точка входа, запускается по cron
├── zabbix/
│   └── template_mikrotik_security_watch.xml
├── tests/
└── requirements.txt
```

## Лицензия

MIT, смотри `LICENSE`.

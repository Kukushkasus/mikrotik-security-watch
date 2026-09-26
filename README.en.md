# 🇺🇸 THIS README IS IN ENGLISH

# 🇷🇺 [РУССКАЯ ВЕРСИЯ → README.md](README.md)

---

# MikroTik Security Watch

A set of scripts plus a Zabbix template that don't just check "is the
router alive" — they watch specifically for **security-relevant events**
on a MikroTik router: a new user shows up, telnet/ftp gets enabled, the
default drop rule disappears from the firewall, RouterOS gets upgraded —
and push an alert into Zabbix.

Most Zabbix+MikroTik templates out there monitor traffic, CPU, uptime.
This one is specifically about configuration security.

---

## How it works

1. `run_check.py` connects to the router over the API (via `librouteros`)
and takes a snapshot of the current state: users, enabled services,
firewall, NTP, RouterOS version.
2. The snapshot is compared against the saved `baseline.json` from the
previous run.
3. Any differences found are turned into events with a severity level
(`info` / `warning` / `high` / `critical`).
4. Both the state and the events are sent to Zabbix via the trapper
protocol (no need to install `zabbix_sender`, pure Python via
`py-zabbix`).
5. The new snapshot is saved as the baseline for the next run.

The script never makes decisions or blocks anything — it only observes
and reports.

---

## Installation

```bash
git clone <this-repository-url>
cd mikrotik-security-watch
pip install -r requirements.txt
```

### 1. Read-only account on the router

Don't use the main admin account — create a dedicated read-only user:

```
/user group add name=zbx-readonly policy=api,read,!write,!policy,!test,!password,!sniff,!sensitive
/user add name=zbx-secwatch group=zbx-readonly password="a-strong-password"
```

### 2. Import the Zabbix template

In Zabbix: **Data collection → Templates → Import** →
`zabbix/template_mikrotik_security_watch.xml`. Then link the
`MikroTik Security Watch` template to the host representing your
router.

### 3. Schedule the run

```bash
python3 run_check.py \
    --router-host 192.168.88.1 \
    --router-user zbx-secwatch \
    --router-password 'a-strong-password' \
    --zabbix-server 10.0.0.5 \
    --zabbix-host "MikroTik Office"
```

Add it to cron (e.g. every 5 minutes):

```
*/5 * * * * cd /path/to/mikrotik-security-watch && python3 run_check.py --router-host ... --zabbix-server ... --zabbix-host "MikroTik Office" >> secwatch.log 2>&1
```

---

## What is tracked

| Event | Severity |
|---|---|
| New user added | high |
| User removed | warning |
| User's group/permissions escalated | high |
| A previously disabled user re-enabled | warning |
| telnet / ftp / www enabled | high |
| Service's allowed access address changed | warning |
| Default drop rule removed from the input chain | critical |
| Firewall rule count decreased | warning |
| NTP client disabled | info |
| RouterOS version changed | info |

Full list of event codes lives in `secwatch/baseline.py`.

---

## Tests

Everything is covered by tests against a fake API — no real router
needed:

```bash
pip install -r requirements-dev.txt
pytest
```

---

## Project structure

```
mikrotik-security-watch/
├── secwatch/
│   ├── collector.py   # takes a router state snapshot
│   ├── baseline.py    # compares two snapshots, finds events
│   └── send.py        # sends metrics to Zabbix
├── run_check.py        # entry point (runs on a cron schedule)
├── zabbix/
│   └── template_mikrotik_security_watch.xml
├── tests/
└── requirements.txt
```

## License

MIT — see `LICENSE`.

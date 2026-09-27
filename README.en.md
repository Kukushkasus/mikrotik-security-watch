# 🇺🇸 THIS README IS IN ENGLISH

# 🇷🇺 [РУССКАЯ ВЕРСИЯ → README.md](README.md)

---

# MikroTik Security Watch

A script and Zabbix template for tracking security events on MikroTik: a new user, telnet/ftp enabled, a missing firewall rule, a RouterOS version change.

Most Zabbix templates for MikroTik track traffic, CPU, uptime. This one tracks configuration security.

---

## How it works

1. `run_check.py` connects to the router and takes a snapshot of the current state: users, enabled services, firewall, NTP, RouterOS version.
2. The snapshot is compared against the saved `baseline.json` from the last run.
3. Any changes found become events with a severity level: `info`, `warning`, `high`, or `critical`.
4. Both the state and the events are sent to Zabbix via the trapper protocol, using the `py-zabbix` library, no need to install `zabbix_sender`.
5. The new state is saved as the baseline for next time.

The script only watches and reports. It never blocks or fixes anything on its own.

---

## Installation

```bash
git clone <this repo URL>
cd mikrotik-security-watch
pip install -r requirements.txt
```

### 1. Create a read-only user on the router

Don't use the main admin account. Create a separate read-only user:

```
/user group add name=zbx-readonly policy=api,read,!write,!policy,!test,!password,!sniff,!sensitive
/user add name=zbx-secwatch group=zbx-readonly password="a-strong-password"
```

### 2. Import the Zabbix template

Zabbix: Data collection → Templates → Import → `zabbix/template_mikrotik_security_watch.xml`. Link the `MikroTik Security Watch` template to your host.

### 3. Set it up

Easiest way is to copy the example config and fill it in once:

```bash
cp config.example.yaml config.yaml
```

Put your router and Zabbix details in there, then just run:

```bash
python3 run_check.py --config config.yaml
```

`config.yaml` is already in `.gitignore`, so the password won't end up in a commit.

If you need to override something temporarily without touching the file, any command-line flag beats whatever is in the config:

```bash
python3 run_check.py --config config.yaml --router-host 192.168.1.1
```

You can also skip the config entirely and just use flags:

```bash
python3 run_check.py \
    --router-host 192.168.88.1 \
    --router-user zbx-secwatch \
    --router-password 'a-strong-password' \
    --zabbix-server 10.0.0.5 \
    --zabbix-host "MikroTik Office"
```

Add it to cron, for example every 5 minutes:

```
*/5 * * * * cd /path/to/mikrotik-security-watch && python3 run_check.py --config config.yaml >> secwatch.log 2>&1
```

---

## What gets tracked

| Event | Severity |
|---|---|
| New user added | high |
| User removed | warning |
| User's permissions raised | high |
| A disabled user re-enabled | warning |
| telnet, ftp, or www enabled | high |
| Service's allowed address changed | warning |
| Drop rule missing in input chain | critical |
| Firewall rule count dropped | warning |
| NTP disabled | info |
| RouterOS version changed | info |

Full list of event codes is in `secwatch/baseline.py`.

---

## Tests

Tests run against a fake API. No real router needed.

```bash
pip install -r requirements-dev.txt
pytest
```

Tests also run automatically on every push to main, via GitHub Actions.

---

## Project structure

```
mikrotik-security-watch/
├── secwatch/
│   ├── collector.py   # takes a router state snapshot
│   ├── baseline.py    # compares snapshots, finds events
│   ├── send.py        # sends metrics to Zabbix
│   └── config.py       # loads config.yaml
├── run_check.py         # entry point, runs on a cron schedule
├── config.example.yaml  # example config, copy to config.yaml
├── zabbix/
│   └── template_mikrotik_security_watch.xml
├── tests/
└── requirements.txt
```

## License

MIT, see `LICENSE`.

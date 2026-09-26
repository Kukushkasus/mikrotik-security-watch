#!/usr/bin/env python3
"""
RU: Точка входа. Запускается по расписанию (cron / systemd timer):

    python3 run_check.py \\
        --router-host 192.168.88.1 --router-user zbx-secwatch --router-password '...' \\
        --zabbix-server 10.0.0.5 --zabbix-host "MikroTik Office"

При каждом запуске:
1. подключается к роутеру и снимает текущее security-состояние
2. сравнивает его с сохранённым baseline.json (снимком с прошлого запуска)
3. найденные изменения превращает в события
4. отправляет и состояние, и события в Zabbix через trapper items
5. сохраняет новый снимок как baseline для следующего раза

EN: Entry point. Meant to be run on a schedule (cron / systemd timer):

    python3 run_check.py \\
        --router-host 192.168.88.1 --router-user zbx-secwatch --router-password '...' \\
        --zabbix-server 10.0.0.5 --zabbix-host "MikroTik Office"

On every run it:
1. connects to the router and takes the current security state snapshot
2. compares it against the saved baseline.json (previous run's snapshot)
3. turns the found changes into events
4. sends both the state and the events to Zabbix via trapper items
5. saves the new snapshot as the baseline for next time
"""

import argparse
import json
import os
import sys

from librouteros import connect

from secwatch.collector import gather_state
from secwatch.baseline import diff_state
from secwatch.send import push_to_zabbix


def load_baseline(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_baseline(path, state):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Снимает security-состояние MikroTik и шлёт события в Zabbix / "
            "Takes a MikroTik security state snapshot and sends events to Zabbix"
        )
    )
    parser.add_argument("--router-host", required=True)
    parser.add_argument("--router-user", required=True)
    parser.add_argument("--router-password", required=True)
    parser.add_argument("--router-port", type=int, default=8728)
    parser.add_argument("--zabbix-server", required=True)
    parser.add_argument("--zabbix-port", type=int, default=10051)
    parser.add_argument(
        "--zabbix-host",
        required=True,
        help=(
            "Имя хоста в Zabbix, к которому привязан шаблон MikroTik Security Watch "
            "/ Zabbix host name the MikroTik Security Watch template is linked to"
        ),
    )
    parser.add_argument(
        "--baseline",
        default="baseline.json",
        help=(
            "Файл, где хранится снимок состояния с прошлого запуска "
            "/ File that stores the state snapshot from the previous run"
        ),
    )
    return parser.parse_args()


def main():
    args = parse_args()

    api = connect(
        username=args.router_user,
        password=args.router_password,
        host=args.router_host,
        port=args.router_port,
    )
    try:
        state = gather_state(api)
    finally:
        api.close()

    old_state = load_baseline(args.baseline)
    events = diff_state(old_state, state)
    save_baseline(args.baseline, state)

    push_to_zabbix(args.zabbix_server, args.zabbix_port, args.zabbix_host, state, events)

    # RU: короткий отчёт в консоль / EN: short console report
    print(f"Готово. Событий найдено / Done. Events found: {len(events)}")
    for e in events:
        print(f"  [{e['severity']}] {e['message']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Точка входа. Запускается по расписанию (cron / systemd timer).

Проще всего один раз завести config.yaml (см. config.example.yaml)
и запускать так:

    python3 run_check.py --config config.yaml

Любой флаг из командной строки, если его указать, перекрывает то, что
написано в config.yaml — так можно временно что-то поменять, не трогая
сам файл.

При каждом запуске:
1. подключается к роутеру и снимает текущее security-состояние
2. сравнивает его с сохранённым baseline.json (снимком с прошлого запуска)
3. найденные изменения превращает в события
4. отправляет и состояние, и события в Zabbix через trapper items
5. сохраняет новый снимок как baseline для следующего раза
"""

import argparse
import json
import os
import sys

from librouteros import connect

from secwatch.collector import gather_state
from secwatch.baseline import diff_state
from secwatch.send import push_to_zabbix
from secwatch.config import load_config, apply_config_defaults

REQUIRED_KEYS = [
    "router_host",
    "router_user",
    "router_password",
    "zabbix_server",
    "zabbix_host",
]


def load_baseline(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_baseline(path, state):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Снимает security-состояние MikroTik и шлёт события в Zabbix"
    )
    parser.add_argument("--config", help="Путь к YAML-конфигу (см. config.example.yaml)")
    parser.add_argument("--router-host", dest="router_host", default=None)
    parser.add_argument("--router-user", dest="router_user", default=None)
    parser.add_argument("--router-password", dest="router_password", default=None)
    parser.add_argument("--router-port", dest="router_port", type=int, default=None)
    parser.add_argument("--zabbix-server", dest="zabbix_server", default=None)
    parser.add_argument("--zabbix-port", dest="zabbix_port", type=int, default=None)
    parser.add_argument(
        "--zabbix-host",
        dest="zabbix_host",
        default=None,
        help="Имя хоста в Zabbix, к которому привязан шаблон MikroTik Security Watch",
    )
    parser.add_argument(
        "--baseline",
        dest="baseline",
        default=None,
        help="Файл, где хранится снимок состояния с прошлого запуска",
    )
    return parser.parse_args(argv)


def resolve_settings(args):
    """Собирает финальные настройки из config-файла (если указан) и CLI-флагов."""
    config = {}
    if args.config:
        config = load_config(args.config)

    settings = apply_config_defaults(vars(args), config)
    settings.pop("config", None)

    settings.setdefault("router_port", 8728)
    settings.setdefault("zabbix_port", 10051)
    settings.setdefault("baseline", "baseline.json")

    missing = [k for k in REQUIRED_KEYS if not settings.get(k)]
    if missing:
        raise SystemExit(
            "Не хватает настроек: "
            + ", ".join(missing)
            + ". Укажи их в config.yaml или флагами командной строки "
            "(например --router-host ...)."
        )

    return settings


def main(argv=None):
    args = parse_args(argv)
    settings = resolve_settings(args)

    api = connect(
        username=settings["router_user"],
        password=settings["router_password"],
        host=settings["router_host"],
        port=settings["router_port"],
    )
    try:
        state = gather_state(api)
    finally:
        api.close()

    old_state = load_baseline(settings["baseline"])
    events = diff_state(old_state, state)
    save_baseline(settings["baseline"], state)

    push_to_zabbix(
        settings["zabbix_server"], settings["zabbix_port"], settings["zabbix_host"], state, events
    )

    print(f"Готово. Событий найдено: {len(events)}")
    for e in events:
        print(f"  [{e['severity']}] {e['message']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

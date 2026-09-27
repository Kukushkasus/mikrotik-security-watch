"""
Загрузка настроек из YAML-конфига и объединение их с аргументами
командной строки.

Приоритет простой: если флаг передан явно в командной строке — он
побеждает. Если нет — берётся значение из конфига. Так можно один раз
прописать конфиг и потом просто запускать `python3 run_check.py`, а
при необходимости что-то переопределить прямо в команде.
"""

import yaml


def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


def apply_config_defaults(args_dict, config):
    merged = dict(config)
    for key, value in args_dict.items():
        if value is not None:
            merged[key] = value
    return merged

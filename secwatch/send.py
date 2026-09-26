"""
RU: Отправляет собранное состояние и найденные события в Zabbix через
zabbix-trapper протокол (используется библиотека py-zabbix, без
необходимости ставить бинарник zabbix_sender отдельно).

Ключи item'ов здесь должны совпадать с ключами в Zabbix-шаблоне
(zabbix/template_mikrotik_security_watch.xml).

EN: Sends the collected state and found events to Zabbix via the
zabbix-trapper protocol (using the py-zabbix library, no need to
install the zabbix_sender binary separately).

The item keys here must match the keys in the Zabbix template
(zabbix/template_mikrotik_security_watch.xml).
"""

import json

from pyzabbix import ZabbixMetric, ZabbixSender

# RU: Сервисы, состояние которых отслеживается отдельными item'ами в Zabbix
# EN: Services whose state is tracked by dedicated Zabbix items
TRACKED_SERVICES = ["telnet", "ftp", "www", "api", "winbox", "ssh"]

SEVERITY_ORDER = {"info": 0, "warning": 1, "high": 2, "critical": 3}


def build_metrics(host, state, events):
    """RU: Собирает список ZabbixMetric из состояния и событий.
    EN: Builds the list of ZabbixMetric objects from state and events."""
    metrics = []

    metrics.append(ZabbixMetric(host, "mikrotik.secwatch.event_count", len(events)))
    metrics.append(
        ZabbixMetric(host, "mikrotik.secwatch.ros_version", state.get("ros_version") or "")
    )
    metrics.append(
        ZabbixMetric(
            host,
            "mikrotik.secwatch.firewall_rule_count",
            state.get("firewall_rule_count") or 0,
        )
    )
    metrics.append(
        ZabbixMetric(
            host,
            "mikrotik.secwatch.firewall_input_has_drop",
            int(bool(state.get("firewall_input_has_drop"))),
        )
    )
    metrics.append(
        ZabbixMetric(
            host, "mikrotik.secwatch.ntp_enabled", int(bool(state.get("ntp_enabled")))
        )
    )

    services_by_name = {s["name"]: s for s in state.get("services", [])}
    for name in TRACKED_SERVICES:
        s = services_by_name.get(name)
        enabled = int(not s["disabled"]) if s else 0
        metrics.append(
            ZabbixMetric(host, f"mikrotik.secwatch.service.{name}", enabled)
        )

    metrics.append(
        ZabbixMetric(
            host, "mikrotik.secwatch.events_json", json.dumps(events, ensure_ascii=False)
        )
    )

    if events:
        worst = max(events, key=lambda e: SEVERITY_ORDER.get(e["severity"], 0))
        metrics.append(ZabbixMetric(host, "mikrotik.secwatch.last_event", worst["message"]))

    return metrics


def push_to_zabbix(zabbix_server, zabbix_port, host, state, events):
    """RU: Отправляет метрики в Zabbix trapper-протоколом.
    EN: Sends metrics to Zabbix using the trapper protocol."""
    metrics = build_metrics(host, state, events)
    sender = ZabbixSender(zabbix_server=zabbix_server, zabbix_port=zabbix_port)
    return sender.send(metrics)

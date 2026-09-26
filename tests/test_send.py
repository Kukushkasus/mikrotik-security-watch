import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secwatch.send import build_metrics


def sample_state():
    return {
        "ros_version": "7.15",
        "firewall_rule_count": 5,
        "firewall_input_has_drop": True,
        "ntp_enabled": True,
        "services": [
            {"name": "telnet", "disabled": True},
            {"name": "www", "disabled": False},
        ],
    }


def metrics_by_key(metrics):
    return {m.key: m.value for m in metrics}


def test_build_metrics_basic_values():
    metrics = build_metrics("TestHost", sample_state(), [])
    by_key = metrics_by_key(metrics)

    assert by_key["mikrotik.secwatch.event_count"] == "0"
    assert by_key["mikrotik.secwatch.ros_version"] == "7.15"
    assert by_key["mikrotik.secwatch.firewall_rule_count"] == "5"
    assert by_key["mikrotik.secwatch.firewall_input_has_drop"] == "1"
    assert by_key["mikrotik.secwatch.ntp_enabled"] == "1"


def test_build_metrics_service_states():
    metrics = build_metrics("TestHost", sample_state(), [])
    by_key = metrics_by_key(metrics)

    assert by_key["mikrotik.secwatch.service.telnet"] == "0"
    assert by_key["mikrotik.secwatch.service.www"] == "1"
    # RU: сервис, который роутер вообще не вернул — считаем выключенным
    # EN: a service the router didn't return at all is treated as disabled
    assert by_key["mikrotik.secwatch.service.ftp"] == "0"


def test_build_metrics_events_json_and_last_event():
    events = [
        {"severity": "warning", "code": "user_removed", "message": "Пользователь удалён"},
        {"severity": "critical", "code": "firewall_drop_removed", "message": "Фаервол ослаблен"},
    ]
    metrics = build_metrics("TestHost", sample_state(), events)
    by_key = metrics_by_key(metrics)

    assert by_key["mikrotik.secwatch.event_count"] == "2"
    parsed = json.loads(by_key["mikrotik.secwatch.events_json"])
    assert len(parsed) == 2
    # RU: last_event должен показывать самое серьёзное событие, а не последнее по списку
    # EN: last_event should show the most severe event, not the last one in the list
    assert by_key["mikrotik.secwatch.last_event"] == "Фаервол ослаблен"


def test_build_metrics_no_events_no_last_event_key():
    metrics = build_metrics("TestHost", sample_state(), [])
    by_key = metrics_by_key(metrics)
    assert "mikrotik.secwatch.last_event" not in by_key

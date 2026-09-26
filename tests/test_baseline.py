import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secwatch.baseline import diff_state


def base_state(**overrides):
    state = {
        "users": [{"name": "admin", "group": "full", "disabled": False}],
        "services": [
            {"name": "telnet", "disabled": True, "port": "23", "address": ""},
            {"name": "www", "disabled": False, "port": "80", "address": ""},
        ],
        "firewall_rule_count": 5,
        "firewall_input_has_drop": True,
        "ntp_enabled": True,
        "ros_version": "7.15",
    }
    state.update(overrides)
    return state


def codes(events):
    return {e["code"] for e in events}


def test_first_run_no_baseline():
    events = diff_state(None, base_state())
    assert codes(events) == {"baseline_created"}


def test_no_changes_no_events():
    old = base_state()
    new = base_state()
    events = diff_state(old, new)
    assert events == []


def test_new_admin_user_detected_as_high():
    old = base_state()
    new = base_state(
        users=[
            {"name": "admin", "group": "full", "disabled": False},
            {"name": "backdoor", "group": "full", "disabled": False},
        ]
    )
    events = diff_state(old, new)
    assert "user_added" in codes(events)
    added = [e for e in events if e["code"] == "user_added"][0]
    assert added["severity"] == "high"
    assert "backdoor" in added["message"]


def test_user_removed_detected():
    old = base_state(
        users=[
            {"name": "admin", "group": "full", "disabled": False},
            {"name": "guest", "group": "read", "disabled": False},
        ]
    )
    new = base_state()
    events = diff_state(old, new)
    assert "user_removed" in codes(events)


def test_user_group_escalation_detected():
    old = base_state(users=[{"name": "admin", "group": "read", "disabled": False}])
    new = base_state(users=[{"name": "admin", "group": "full", "disabled": False}])
    events = diff_state(old, new)
    assert "user_group_changed" in codes(events)
    e = [x for x in events if x["code"] == "user_group_changed"][0]
    assert e["severity"] == "high"


def test_telnet_enabled_is_high_severity():
    old = base_state()
    new = base_state(
        services=[
            {"name": "telnet", "disabled": False, "port": "23", "address": ""},
            {"name": "www", "disabled": False, "port": "80", "address": ""},
        ]
    )
    events = diff_state(old, new)
    telnet_events = [e for e in events if e["code"] == "service_enabled"]
    assert len(telnet_events) == 1
    assert telnet_events[0]["severity"] == "high"


def test_non_risky_service_enabled_is_warning():
    old = base_state(
        services=[
            {"name": "telnet", "disabled": True, "port": "23", "address": ""},
            {"name": "api", "disabled": True, "port": "8728", "address": ""},
        ]
    )
    new = base_state(
        services=[
            {"name": "telnet", "disabled": True, "port": "23", "address": ""},
            {"name": "api", "disabled": False, "port": "8728", "address": ""},
        ]
    )
    events = diff_state(old, new)
    api_events = [e for e in events if e["code"] == "service_enabled"]
    assert len(api_events) == 1
    assert api_events[0]["severity"] == "warning"


def test_service_access_address_change_detected():
    old = base_state()
    new = base_state(
        services=[
            {"name": "telnet", "disabled": True, "port": "23", "address": ""},
            {"name": "www", "disabled": False, "port": "80", "address": "0.0.0.0/0"},
        ]
    )
    events = diff_state(old, new)
    assert "service_access_changed" in codes(events)


def test_firewall_drop_removed_is_critical():
    old = base_state(firewall_input_has_drop=True)
    new = base_state(firewall_input_has_drop=False)
    events = diff_state(old, new)
    assert "firewall_drop_removed" in codes(events)
    e = [x for x in events if x["code"] == "firewall_drop_removed"][0]
    assert e["severity"] == "critical"


def test_firewall_rule_count_decreased():
    old = base_state(firewall_rule_count=10)
    new = base_state(firewall_rule_count=6)
    events = diff_state(old, new)
    assert "firewall_rules_removed" in codes(events)


def test_firewall_rule_count_increase_not_flagged():
    old = base_state(firewall_rule_count=5)
    new = base_state(firewall_rule_count=8)
    events = diff_state(old, new)
    assert "firewall_rules_removed" not in codes(events)


def test_ntp_disabled_detected():
    old = base_state(ntp_enabled=True)
    new = base_state(ntp_enabled=False)
    events = diff_state(old, new)
    assert "ntp_disabled" in codes(events)


def test_ros_version_change_detected():
    old = base_state(ros_version="7.15")
    new = base_state(ros_version="7.16")
    events = diff_state(old, new)
    assert "ros_version_changed" in codes(events)


def test_multiple_events_in_one_diff():
    old = base_state()
    new = base_state(
        users=[
            {"name": "admin", "group": "full", "disabled": False},
            {"name": "backdoor", "group": "full", "disabled": False},
        ],
        services=[
            {"name": "telnet", "disabled": False, "port": "23", "address": ""},
            {"name": "www", "disabled": False, "port": "80", "address": ""},
        ],
        firewall_input_has_drop=False,
    )
    events = diff_state(old, new)
    found = codes(events)
    assert {"user_added", "service_enabled", "firewall_drop_removed"} <= found

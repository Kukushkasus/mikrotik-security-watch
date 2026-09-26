import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secwatch.collector import gather_state


class FakeApi:
    """RU: Имитирует интерфейс librouteros: api(cmd=...) -> список словарей.
    EN: Mimics the librouteros interface: api(cmd=...) -> list of dicts."""

    def __init__(self, responses):
        self.responses = responses

    def __call__(self, cmd, **kwargs):
        return self.responses.get(cmd, [])


def make_fake_api(overrides=None):
    responses = {
        "/user/print": [{"name": "admin", "group": "full", "disabled": False}],
        "/ip/service/print": [
            {"name": "telnet", "disabled": True, "port": "23", "address": ""},
            {"name": "www", "disabled": False, "port": "80", "address": ""},
        ],
        "/ip/firewall/filter/print": [
            {"chain": "input", "action": "accept", "disabled": False},
            {"chain": "input", "action": "drop", "disabled": False},
        ],
        "/system/ntp/client/print": [{"enabled": True}],
        "/system/identity/print": [{"name": "TestRouter"}],
        "/system/resource/print": [{"version": "7.15"}],
    }
    if overrides:
        responses.update(overrides)
    return FakeApi(responses)


def test_gather_state_basic_fields():
    api = make_fake_api()
    state = gather_state(api)

    assert state["identity"] == "TestRouter"
    assert state["ros_version"] == "7.15"
    assert state["ntp_enabled"] is True
    assert state["firewall_rule_count"] == 2
    assert state["firewall_input_has_drop"] is True


def test_gather_state_users_sorted():
    api = make_fake_api(
        {
            "/user/print": [
                {"name": "zorro", "group": "full", "disabled": False},
                {"name": "admin", "group": "full", "disabled": False},
            ]
        }
    )
    state = gather_state(api)
    names = [u["name"] for u in state["users"]]
    assert names == ["admin", "zorro"]


def test_gather_state_services_disabled_flag():
    api = make_fake_api()
    state = gather_state(api)
    services = {s["name"]: s for s in state["services"]}
    assert services["telnet"]["disabled"] is True
    assert services["www"]["disabled"] is False


def test_gather_state_no_drop_rule():
    api = make_fake_api(
        {
            "/ip/firewall/filter/print": [
                {"chain": "input", "action": "accept", "disabled": False},
            ]
        }
    )
    state = gather_state(api)
    assert state["firewall_input_has_drop"] is False


def test_gather_state_disabled_drop_rule_does_not_count():
    api = make_fake_api(
        {
            "/ip/firewall/filter/print": [
                {"chain": "input", "action": "drop", "disabled": True},
            ]
        }
    )
    state = gather_state(api)
    assert state["firewall_input_has_drop"] is False


def test_gather_state_ntp_missing_is_none():
    api = make_fake_api({"/system/ntp/client/print": []})
    state = gather_state(api)
    assert state["ntp_enabled"] is None

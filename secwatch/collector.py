"""
RU: Собирает security-состояние роутера MikroTik: пользователи, включённые
сервисы, состояние фаервола, NTP, версия RouterOS.

Ничего не решает сам — просто снимает "снимок" текущего состояния.
Сравнением снимков (baseline vs текущий) занимается baseline.py.

Функция gather_state() принимает объект api — это может быть реальное
подключение librouteros.connect(...), либо любой другой объект с тем же
интерфейсом api(cmd=...) -> список словарей. Это специально сделано так,
чтобы юнит-тесты могли подсовывать сюда фейковый api без реального роутера.

EN: Collects the security-relevant state of a MikroTik router: users,
enabled services, firewall status, NTP, RouterOS version.

Does not make any decisions itself — just takes a "snapshot" of the
current state. Comparing snapshots (baseline vs current) is done in
baseline.py.

gather_state() accepts an api object — either a real
librouteros.connect(...) connection, or any object with the same
api(cmd=...) -> list[dict] interface. This is intentional, so unit
tests can pass in a fake api without a real router.
"""


def _as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "yes", "1")
    return bool(value)


def gather_state(api):
    """RU: Снимает текущее security-состояние роутера через api.
    EN: Takes the current security state snapshot of the router via api."""
    state = {}

    users = list(api(cmd="/user/print"))
    state["users"] = sorted(
        [
            {
                "name": u.get("name"),
                "group": u.get("group"),
                "disabled": _as_bool(u.get("disabled")),
            }
            for u in users
        ],
        key=lambda x: x["name"] or "",
    )

    services = list(api(cmd="/ip/service/print"))
    state["services"] = sorted(
        [
            {
                "name": s.get("name"),
                "disabled": _as_bool(s.get("disabled")),
                "port": s.get("port"),
                "address": s.get("address", ""),
            }
            for s in services
        ],
        key=lambda x: x["name"] or "",
    )

    firewall = list(api(cmd="/ip/firewall/filter/print"))
    state["firewall_rule_count"] = len(firewall)
    state["firewall_input_has_drop"] = any(
        r.get("chain") == "input"
        and r.get("action") == "drop"
        and not _as_bool(r.get("disabled"))
        for r in firewall
    )

    try:
        ntp = list(api(cmd="/system/ntp/client/print"))
        state["ntp_enabled"] = _as_bool(ntp[0].get("enabled")) if ntp else None
    except Exception:
        state["ntp_enabled"] = None

    identity = list(api(cmd="/system/identity/print"))
    state["identity"] = identity[0].get("name") if identity else None

    resource = list(api(cmd="/system/resource/print"))
    state["ros_version"] = resource[0].get("version") if resource else None

    return state

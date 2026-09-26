"""
RU: Сравнивает два снимка состояния роутера (старый и новый) и находит
security-значимые изменения: новый пользователь, включённый telnet/ftp,
пропавшее правило drop в фаерволе и т.д.

EN: Compares two router state snapshots (old and new) and finds
security-relevant changes: a new user, telnet/ftp enabled,
a missing default drop rule in the firewall, etc.

RU: Каждое событие — это словарь:
EN: Each event is a dict:
{
    "severity": "info" | "warning" | "high" | "critical",
    "code": "user_added",
    "message": "человеко-читаемое описание / human-readable description",
}
"""

# RU: Сервисы, которые считаются рискованными, если их включили
# EN: Services considered risky when enabled
RISKY_SERVICES = {"telnet", "ftp", "www"}


def diff_state(old, new):
    """RU: Сравнивает old и new, возвращает список событий.
    EN: Compares old and new, returns a list of events."""
    events = []

    if old is None:
        events.append(
            {
                "severity": "info",
                "code": "baseline_created",
                "message": (
                    "Первый запуск — сохранён базовый снимок состояния роутера "
                    "/ First run — baseline router state snapshot saved"
                ),
            }
        )
        return events

    events.extend(_diff_users(old, new))
    events.extend(_diff_services(old, new))
    events.extend(_diff_firewall(old, new))
    events.extend(_diff_misc(old, new))

    return events


def _diff_users(old, new):
    events = []
    old_users = {u["name"]: u for u in old.get("users", [])}
    new_users = {u["name"]: u for u in new.get("users", [])}

    for name in new_users.keys() - old_users.keys():
        u = new_users[name]
        events.append(
            {
                "severity": "high",
                "code": "user_added",
                "message": (
                    f'Добавлен новый пользователь "{name}" (группа {u["group"]}) '
                    f'/ New user "{name}" added (group {u["group"]})'
                ),
            }
        )

    for name in old_users.keys() - new_users.keys():
        events.append(
            {
                "severity": "warning",
                "code": "user_removed",
                "message": f'Пользователь "{name}" удалён / User "{name}" removed',
            }
        )

    for name in new_users.keys() & old_users.keys():
        old_u, new_u = old_users[name], new_users[name]
        if old_u["group"] != new_u["group"]:
            events.append(
                {
                    "severity": "high",
                    "code": "user_group_changed",
                    "message": (
                        f'У пользователя "{name}" изменена группа: '
                        f'{old_u["group"]} -> {new_u["group"]} '
                        f'/ User "{name}" group changed: '
                        f'{old_u["group"]} -> {new_u["group"]}'
                    ),
                }
            )
        if old_u["disabled"] and not new_u["disabled"]:
            events.append(
                {
                    "severity": "warning",
                    "code": "user_enabled",
                    "message": (
                        f'Отключённый пользователь "{name}" снова включён '
                        f'/ Previously disabled user "{name}" re-enabled'
                    ),
                }
            )

    return events


def _diff_services(old, new):
    events = []
    old_services = {s["name"]: s for s in old.get("services", [])}
    new_services = {s["name"]: s for s in new.get("services", [])}

    for name, s in new_services.items():
        old_s = old_services.get(name)
        if old_s is None:
            continue

        if old_s["disabled"] and not s["disabled"]:
            severity = "high" if name in RISKY_SERVICES else "warning"
            events.append(
                {
                    "severity": severity,
                    "code": "service_enabled",
                    "message": (
                        f'Сервис "{name}" включён (порт {s.get("port")}) '
                        f'/ Service "{name}" enabled (port {s.get("port")})'
                    ),
                }
            )

        if (old_s.get("address") or "") != (s.get("address") or ""):
            events.append(
                {
                    "severity": "warning",
                    "code": "service_access_changed",
                    "message": (
                        f'У сервиса "{name}" изменён разрешённый адрес доступа: '
                        f'"{old_s.get("address") or "любой"}" -> '
                        f'"{s.get("address") or "любой"}" '
                        f'/ Service "{name}" allowed address changed: '
                        f'"{old_s.get("address") or "any"}" -> '
                        f'"{s.get("address") or "any"}"'
                    ),
                }
            )

    return events


def _diff_firewall(old, new):
    events = []

    if old.get("firewall_input_has_drop") and not new.get("firewall_input_has_drop"):
        events.append(
            {
                "severity": "critical",
                "code": "firewall_drop_removed",
                "message": (
                    "В цепочке input пропало активное правило drop по умолчанию — "
                    "фаервол мог быть ослаблен / "
                    "The default active drop rule in the input chain is gone — "
                    "the firewall may have been weakened"
                ),
            }
        )

    old_count = old.get("firewall_rule_count")
    new_count = new.get("firewall_rule_count")
    if old_count is not None and new_count is not None and new_count < old_count:
        events.append(
            {
                "severity": "warning",
                "code": "firewall_rules_removed",
                "message": (
                    f"Количество правил фаервола уменьшилось: "
                    f"{old_count} -> {new_count} / "
                    f"Firewall rule count decreased: {old_count} -> {new_count}"
                ),
            }
        )

    return events


def _diff_misc(old, new):
    events = []

    if old.get("ntp_enabled") and new.get("ntp_enabled") is False:
        events.append(
            {
                "severity": "info",
                "code": "ntp_disabled",
                "message": (
                    "NTP-клиент отключён — время на роутере может разъехаться, "
                    "логи станут менее надёжными / "
                    "NTP client disabled — router time may drift, "
                    "making logs less reliable"
                ),
            }
        )

    old_ver = old.get("ros_version")
    new_ver = new.get("ros_version")
    if old_ver and new_ver and old_ver != new_ver:
        events.append(
            {
                "severity": "info",
                "code": "ros_version_changed",
                "message": (
                    f"Версия RouterOS изменилась: {old_ver} -> {new_ver} / "
                    f"RouterOS version changed: {old_ver} -> {new_ver}"
                ),
            }
        )

    return events

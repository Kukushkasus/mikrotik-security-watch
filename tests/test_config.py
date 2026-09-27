import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secwatch.config import load_config, apply_config_defaults
from run_check import parse_args, resolve_settings


def write_temp_yaml(content):
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    )
    f.write(content)
    f.close()
    return f.name


def test_load_config_basic():
    path = write_temp_yaml(
        "router_host: 192.168.88.1\nrouter_user: admin\nrouter_password: secret\n"
    )
    try:
        config = load_config(path)
        assert config["router_host"] == "192.168.88.1"
        assert config["router_user"] == "admin"
    finally:
        os.unlink(path)


def test_load_empty_config_returns_dict():
    path = write_temp_yaml("")
    try:
        config = load_config(path)
        assert config == {}
    finally:
        os.unlink(path)


def test_apply_config_defaults_cli_overrides_config():
    config = {"router_host": "from-config", "router_port": 8728}
    args_dict = {"router_host": "from-cli", "router_port": None}
    merged = apply_config_defaults(args_dict, config)
    assert merged["router_host"] == "from-cli"
    assert merged["router_port"] == 8728


def test_apply_config_defaults_config_only():
    config = {"router_host": "from-config"}
    args_dict = {"router_host": None, "router_user": None}
    merged = apply_config_defaults(args_dict, config)
    assert merged["router_host"] == "from-config"
    assert merged.get("router_user") is None


def test_resolve_settings_from_config_file():
    path = write_temp_yaml(
        "router_host: 192.168.88.1\n"
        "router_user: zbx\n"
        "router_password: secret\n"
        "zabbix_server: 10.0.0.5\n"
        "zabbix_host: MyRouter\n"
    )
    try:
        args = parse_args(["--config", path])
        settings = resolve_settings(args)
        assert settings["router_host"] == "192.168.88.1"
        assert settings["router_port"] == 8728  # значение по умолчанию
        assert settings["zabbix_port"] == 10051  # значение по умолчанию
    finally:
        os.unlink(path)


def test_resolve_settings_cli_overrides_config_file():
    path = write_temp_yaml(
        "router_host: from-config\n"
        "router_user: zbx\n"
        "router_password: secret\n"
        "zabbix_server: 10.0.0.5\n"
        "zabbix_host: MyRouter\n"
    )
    try:
        args = parse_args(["--config", path, "--router-host", "from-cli"])
        settings = resolve_settings(args)
        assert settings["router_host"] == "from-cli"
    finally:
        os.unlink(path)


def test_resolve_settings_missing_required_raises():
    args = parse_args(["--router-host", "192.168.88.1"])
    try:
        resolve_settings(args)
        assert False, "должно было упасть из-за нехватки настроек"
    except SystemExit as e:
        assert "router_user" in str(e)


def test_resolve_settings_pure_cli_no_config():
    args = parse_args(
        [
            "--router-host",
            "192.168.88.1",
            "--router-user",
            "zbx",
            "--router-password",
            "secret",
            "--zabbix-server",
            "10.0.0.5",
            "--zabbix-host",
            "MyRouter",
        ]
    )
    settings = resolve_settings(args)
    assert settings["router_host"] == "192.168.88.1"
    assert settings["router_port"] == 8728

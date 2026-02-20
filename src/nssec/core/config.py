"""YAML configuration management for nssec."""

import os
import re
from pathlib import Path
from typing import Any

import yaml

from nssec.core.server_types import ServerType

_SERVER_TYPE_CONFIGS = {
    "core": {
        "waf": {
            "enabled": True,
            "admin_ui_protection": True,
            "api_rate_limiting": True,
            "rate_limit_requests": 100,
            "rate_limit_window": 60,
        },
        "mysql": {"lock_down": True, "allowed_subnets": []},
    },
    "ndp": {
        "mtls": {
            "enabled": True,
            "devices": ["poly", "yealink", "grandstream", "panasonic"],
            "cert_validity_days": 365,
        },
        "waf": {"enabled": True, "endpoints_protection": True},
    },
    "recording": {
        "waf": {
            "enabled": True,
            "upload_limit": "5GB",
            "allowed_upload_paths": ["/LiCf/upload"],
        },
    },
}

_TYPE_TO_SECTIONS = {
    ServerType.CORE: ["core"],
    ServerType.NDP: ["ndp"],
    ServerType.RECORDING: ["recording"],
    ServerType.COMBO: ["core", "ndp", "recording"],
}


def _env_var_constructor(loader: yaml.SafeLoader, node: yaml.ScalarNode) -> str:
    """YAML constructor for environment variable interpolation.

    Supports ${VAR} and ${VAR:-default} syntax.
    """
    value = loader.construct_scalar(node)

    # Match ${VAR} or ${VAR:-default}
    pattern = r"\$\{([^}:]+)(?::-([^}]*))?\}"

    def replace_env(match):
        var_name = match.group(1)
        default = match.group(2) if match.group(2) is not None else ""
        return os.environ.get(var_name, default)

    return re.sub(pattern, replace_env, value)


class _EnvSafeLoader(yaml.SafeLoader):
    """YAML SafeLoader subclass with environment variable support.

    Uses a subclass to avoid mutating the global yaml.SafeLoader.
    """


_EnvSafeLoader.add_implicit_resolver(
    "!env",
    re.compile(r"\$\{[^}]+\}"),
    None,
)
_EnvSafeLoader.add_constructor("!env", _env_var_constructor)


def _get_env_loader() -> type:
    """Return the YAML loader with environment variable support."""
    return _EnvSafeLoader


def load_config(config_path: Path) -> dict[str, Any]:
    """Load configuration from YAML file with environment variable interpolation.

    Args:
        config_path: Path to config.yaml file or directory containing it.

    Returns:
        Configuration dictionary.

    Raises:
        FileNotFoundError: If config file doesn't exist.
        yaml.YAMLError: If config file is invalid YAML.
    """
    if config_path.is_dir():
        config_path = config_path / "config.yaml"

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path) as f:
        config = yaml.load(f, Loader=_get_env_loader())

    return config or {}


def save_config(config: dict[str, Any], config_path: Path) -> None:
    """Save configuration to YAML file with secure permissions.

    Args:
        config: Configuration dictionary.
        config_path: Path to save config.yaml file.

    Note:
        Config files are created with mode 0o600 (owner read/write only)
        for security purposes.
    """
    if config_path.is_dir():
        config_path = config_path / "config.yaml"

    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Use os.open() with explicit mode for atomic secure file creation
    # This avoids the race condition of creating then chmod'ing
    fd = os.open(
        str(config_path),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,  # Owner read/write only
    )
    # os.fdopen takes ownership of fd — it will close it when the file
    # object is closed (including on exceptions within the with block)
    with os.fdopen(fd, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def create_default_config(config_path: Path, server_type: ServerType) -> None:
    """Generate and save a default configuration file."""
    config = _generate_default_config(server_type)
    save_config(config, config_path)


def _generate_default_config(server_type: ServerType) -> dict[str, Any]:
    """Generate default configuration based on server type."""
    st = server_type.value if server_type != ServerType.UNKNOWN else "auto"
    config: dict[str, Any] = {
        "# NS-Security Configuration": None,
        "# Generated for server type": server_type.value,
        "server": {"type": st, "hostname": "${HOSTNAME:-localhost}"},
        "base": {
            "firewall": {
                "enabled": True,
                "netsapiens_ips": [],
                "admin_ips": [],
                "admin_subnets": [],
            },
            "ssh": {"lock_down": True, "allowed_ips": []},
        },
    }

    for section in _TYPE_TO_SECTIONS.get(server_type, []):
        config[section] = _SERVER_TYPE_CONFIGS[section]

    return config


def get_config_value(config: dict[str, Any], key_path: str, default: Any = None) -> Any:
    """Get a nested configuration value using dot notation.

    Args:
        config: Configuration dictionary.
        key_path: Dot-separated path to value (e.g., "core.waf.enabled").
        default: Default value if key not found.

    Returns:
        Configuration value or default.
    """
    keys = key_path.split(".")
    value = config

    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default

    return value


def validate_config(config: dict[str, Any]) -> list:
    """Validate configuration and return list of issues.

    Args:
        config: Configuration dictionary.

    Returns:
        List of validation error messages (empty if valid).
    """
    errors = []

    # Check server type
    server_type = get_config_value(config, "server.type")
    if server_type and server_type not in ["auto", "core", "ndp", "recording", "qos", "combo"]:
        errors.append(f"Invalid server type: {server_type}")

    # Check firewall config
    if get_config_value(config, "base.firewall.enabled"):
        admin_ips = get_config_value(config, "base.firewall.admin_ips", [])
        if not admin_ips:
            errors.append(
                "Warning: No admin IPs configured. "
                "Only NetSapiens TAC IPs will have administrative access."
            )

    # Check mTLS config on NDP
    if get_config_value(config, "ndp.mtls.enabled"):
        devices = get_config_value(config, "ndp.mtls.devices", [])
        valid_devices = ["poly", "yealink", "grandstream", "panasonic", "htek"]
        for device in devices:
            if device not in valid_devices:
                errors.append(f"Invalid mTLS device type: {device}")

    return errors

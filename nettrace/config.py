from __future__ import annotations

import copy
from importlib import resources
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG: dict[str, Any] = {
    "thresholds": {
        "beacon_min_events": 5,
        "beacon_max_cv": 0.25,
        "beacon_min_interval_seconds": 2,
        "beacon_max_interval_seconds": 3_600,
        "beacon_max_group_events": 10_000,
        "dga_entropy_threshold": 3.4,
        "dga_score_threshold": 0.6,
        "high_frequency_connections": 50,
        "long_tls_session_seconds": 900,
        "tls_sni_length_threshold": 24,
    },
    "intel": {
        "known_bad_domains": "data/known_bad_domains.txt",
        "known_bad_ips": "data/known_bad_ips.txt",
        "suspicious_user_agents": "data/suspicious_user_agents.txt",
    },
    "misp": {
        "enabled": False,
        "url": "",
        "api_key_env": "NETTRACE_MISP_API_KEY",
        "verify_ssl": True,
        "max_iocs": 5_000,
        "batch_size": 100,
        "timeout_seconds": 10,
    },
    "protocols": {
        "http_ports": [80, 8000, 8080, 8888],
        "tcp_overlap_policy": "reject-conflicting-overlap",
    },
    "limits": {
        "max_dns_events": 100_000,
        "max_http_events": 100_000,
        "max_tls_events": 100_000,
        "max_ftp_events": 100_000,
        "max_flows": 50_000,
        "max_timeline_entries": 100_000,
        "max_flow_samples": 256,
        "max_findings": 20_000,
        "max_tcp_streams": 10_000,
        "max_tcp_stream_buffer_bytes": 1_048_576,
        "max_tcp_pending_segments": 256,
        "max_tcp_total_buffer_bytes": 67_108_864,
        "max_tcp_stream_idle_seconds": 300,
        "max_fragment_age_seconds": 60,
    },
}

DEFAULT_THRESHOLDS_PATH = Path(__file__).parent / "rules" / "thresholds.yaml"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
INTEL_KEYS = ("known_bad_domains", "known_bad_ips", "suspicious_user_agents")


class ConfigError(ValueError):
    pass


def package_data_path(filename: str) -> str:
    return str(resources.files("nettrace").joinpath("data", filename))


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a mapping.")
    return value


def _number(value: Any, name: str, minimum: float = 0, maximum: float | None = None) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{name} must be a number.")
    if value < minimum or (maximum is not None and value > maximum):
        range_text = f" between {minimum} and {maximum}" if maximum is not None else f" at least {minimum}"
        raise ConfigError(f"{name} must be{range_text}.")


def _positive_integer(value: Any, name: str, minimum: int = 1) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConfigError(f"{name} must be an integer of at least {minimum}.")


def _reject_unknown_keys(loaded: dict[str, Any] | None, name: str) -> None:
    """Bug #13: a misspelled key like 'high_frequncy_connections' previously
    merged in silently while the real threshold stayed at its default, with
    no warning. Unknown keys at these two levels are now a hard config error."""
    if not loaded:
        return
    for section in ("thresholds", "misp", "limits", "protocols", "intel"):
        section_value = loaded.get(section)
        if not isinstance(section_value, dict):
            continue
        known = set(INTEL_KEYS) if section == "intel" else set(DEFAULT_CONFIG.get(section, {}).keys())
        unknown = set(section_value.keys()) - known
        if unknown:
            raise ConfigError(
                f"Unknown key(s) in {name} {section}: {sorted(unknown)}. "
                f"Known keys: {sorted(known)}."
            )
    known_top = set(DEFAULT_CONFIG.keys()) | {"intel"}
    unknown_top = set(loaded.keys()) - known_top
    if unknown_top:
        raise ConfigError(f"Unknown top-level key(s) in {name}: {sorted(unknown_top)}.")


def validate_config(config: dict[str, Any]) -> None:
    thresholds = _mapping(config.get("thresholds"), "thresholds")
    _positive_integer(thresholds.get("beacon_min_events"), "thresholds.beacon_min_events", 2)
    _number(thresholds.get("beacon_max_cv"), "thresholds.beacon_max_cv")
    _number(thresholds.get("beacon_min_interval_seconds"), "thresholds.beacon_min_interval_seconds")
    _number(thresholds.get("beacon_max_interval_seconds"), "thresholds.beacon_max_interval_seconds")
    _positive_integer(thresholds.get("beacon_max_group_events"), "thresholds.beacon_max_group_events", 2)
    _number(thresholds.get("dga_entropy_threshold"), "thresholds.dga_entropy_threshold")
    _number(thresholds.get("dga_score_threshold"), "thresholds.dga_score_threshold", 0, 1)
    _positive_integer(thresholds.get("high_frequency_connections"), "thresholds.high_frequency_connections")
    _number(thresholds.get("long_tls_session_seconds"), "thresholds.long_tls_session_seconds")
    _positive_integer(thresholds.get("tls_sni_length_threshold"), "thresholds.tls_sni_length_threshold")

    intel = _mapping(config.get("intel"), "intel")
    for key in INTEL_KEYS:
        if not isinstance(intel.get(key), str):
            raise ConfigError(f"intel.{key} must be a path string.")

    misp = _mapping(config.get("misp"), "misp")
    for key in ("enabled", "verify_ssl"):
        if not isinstance(misp.get(key), bool):
            raise ConfigError(f"misp.{key} must be true or false.")
    for key in ("url", "api_key_env"):
        if not isinstance(misp.get(key), str):
            raise ConfigError(f"misp.{key} must be a string.")
    if "api_key" in misp and not isinstance(misp["api_key"], str):
        raise ConfigError("misp.api_key must be a string when provided.")
    _positive_integer(misp.get("max_iocs"), "misp.max_iocs")
    _positive_integer(misp.get("batch_size"), "misp.batch_size")
    _number(misp.get("timeout_seconds"), "misp.timeout_seconds", 0.1)

    protocols = _mapping(config.get("protocols"), "protocols")
    http_ports = protocols.get("http_ports")
    if not isinstance(http_ports, list) or not http_ports:
        raise ConfigError("protocols.http_ports must be a non-empty list of ports.")
    if any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535 for port in http_ports):
        raise ConfigError("protocols.http_ports entries must be integers between 1 and 65535.")
    overlap_policy = protocols.get("tcp_overlap_policy")
    if overlap_policy not in {"first-seen-wins", "last-seen-wins", "reject-conflicting-overlap"}:
        raise ConfigError(
            "protocols.tcp_overlap_policy must be one of: first-seen-wins, "
            "last-seen-wins, reject-conflicting-overlap."
        )

    limits = _mapping(config.get("limits"), "limits")
    for key in DEFAULT_CONFIG["limits"]:
        _positive_integer(limits.get(key), f"limits.{key}")


def resolve_intel_paths(config: dict[str, Any], base_dir: Path, overridden_keys: set[str] | None = None) -> dict[str, Any]:
    resolved = copy.deepcopy(config)
    intel = resolved.get("intel", {})
    overridden_keys = overridden_keys or set()
    for key in INTEL_KEYS:
        value = intel.get(key)
        if not value:
            continue
        path = Path(value)
        if key not in overridden_keys and value == DEFAULT_CONFIG["intel"][key]:
            intel[key] = package_data_path(path.name)
        elif not path.is_absolute():
            intel[key] = str((base_dir / path).resolve())
    return resolved


def load_config(path: Path, explicit: bool = False) -> dict[str, Any]:
    """Load config.

    ``explicit`` should be True when the path came from a user-provided ``-c``
    flag rather than the packaged default filename. Bug #12: previously a
    missing file silently fell back to defaults in both cases, so a typo'd
    ``-c confg.yaml`` looked like it worked while actually using defaults.
    """
    config = DEFAULT_CONFIG
    if DEFAULT_THRESHOLDS_PATH.exists():
        with DEFAULT_THRESHOLDS_PATH.open("r", encoding="utf-8") as handle:
            try:
                loaded_thresholds = yaml.safe_load(handle) or {}
            except yaml.YAMLError as exc:
                raise ConfigError(f"Invalid packaged threshold YAML: {exc}") from exc
        loaded_thresholds = _mapping(loaded_thresholds, "packaged thresholds")
        thresholds = loaded_thresholds.get("thresholds", loaded_thresholds)
        _mapping(thresholds, "packaged thresholds.thresholds")
        config = deep_merge(config, {"thresholds": thresholds})
    if not path.exists():
        if explicit:
            raise ConfigError(f"Config file not found: {path}")
        validate_config(config)
        return resolve_intel_paths(config, PROJECT_ROOT)
    with path.open("r", encoding="utf-8") as handle:
        try:
            loaded = yaml.safe_load(handle) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    loaded = _mapping(loaded, "config root")
    if "intel" in loaded:
        _mapping(loaded["intel"], "intel")
    _reject_unknown_keys(loaded, str(path))
    overridden_keys = set((loaded.get("intel") or {}).keys())
    merged = deep_merge(config, loaded)
    validate_config(merged)
    return resolve_intel_paths(merged, path.resolve().parent, overridden_keys)

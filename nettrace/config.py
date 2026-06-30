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
        "api_key": "",
        "verify_ssl": True,
    },
}

DEFAULT_THRESHOLDS_PATH = Path(__file__).parent / "rules" / "thresholds.yaml"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
INTEL_KEYS = ("known_bad_domains", "known_bad_ips", "suspicious_user_agents")


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


def load_config(path: Path) -> dict[str, Any]:
    config = DEFAULT_CONFIG
    if DEFAULT_THRESHOLDS_PATH.exists():
        with DEFAULT_THRESHOLDS_PATH.open("r", encoding="utf-8") as handle:
            loaded_thresholds = yaml.safe_load(handle) or {}
        thresholds = loaded_thresholds.get("thresholds", loaded_thresholds)
        config = deep_merge(config, {"thresholds": thresholds})
    if not path.exists():
        return resolve_intel_paths(config, PROJECT_ROOT)
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    overridden_keys = set((loaded.get("intel") or {}).keys())
    return resolve_intel_paths(deep_merge(config, loaded), path.resolve().parent, overridden_keys)

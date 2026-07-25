from pathlib import Path

import pytest

from nettrace.config import ConfigError, load_config, package_data_path


def test_load_config_uses_threshold_rule_defaults_when_project_config_missing():
    config = load_config(Path("does-not-exist.yaml"))

    assert config["thresholds"]["beacon_min_events"] == 5
    assert config["thresholds"]["dga_score_threshold"] == 0.6
    assert config["intel"]["known_bad_domains"] == package_data_path("known_bad_domains.txt")
    assert config["intel"]["known_bad_ips"] == package_data_path("known_bad_ips.txt")
    assert config["intel"]["suspicious_user_agents"] == package_data_path("suspicious_user_agents.txt")
    assert Path(config["intel"]["known_bad_domains"]).is_file()


def test_load_config_resolves_intel_paths_relative_to_config_file(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
intel:
  known_bad_domains: data/domains.txt
  known_bad_ips: data/ips.txt
  suspicious_user_agents: data/user_agents.txt
""".strip(),
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config["intel"]["known_bad_domains"] == str((tmp_path / "data" / "domains.txt").resolve())
    assert config["intel"]["known_bad_ips"] == str((tmp_path / "data" / "ips.txt").resolve())
    assert config["intel"]["suspicious_user_agents"] == str((tmp_path / "data" / "user_agents.txt").resolve())


def test_load_config_rejects_non_mapping_root(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("- item\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="config root must be a mapping"):
        load_config(config_path)


def test_load_config_rejects_invalid_threshold_and_port_types(tmp_path):
    bad_threshold = tmp_path / "bad-threshold.yaml"
    bad_threshold.write_text("thresholds:\n  beacon_min_events: five\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="beacon_min_events"):
        load_config(bad_threshold)

    bad_port = tmp_path / "bad-port.yaml"
    bad_port.write_text("protocols:\n  http_ports: [80, invalid]\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="http_ports"):
        load_config(bad_port)

    bad_policy = tmp_path / "bad-policy.yaml"
    bad_policy.write_text("protocols:\n  tcp_overlap_policy: maybe\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="tcp_overlap_policy"):
        load_config(bad_policy)


def test_load_config_errors_on_missing_explicit_path(tmp_path):
    # Bug #12: a user-specified -c path that doesn't exist must error, not
    # silently fall back to defaults.
    missing = tmp_path / "confg.yaml"  # typo'd filename, on purpose

    with pytest.raises(ConfigError, match="Config file not found"):
        load_config(missing, explicit=True)


def test_load_config_still_defaults_when_implicit_path_missing(tmp_path):
    # Unchanged behavior: the packaged default config.yaml is optional.
    missing = tmp_path / "config.yaml"

    config = load_config(missing, explicit=False)

    assert config["thresholds"]["high_frequency_connections"] == 50


def test_load_config_rejects_unknown_threshold_key(tmp_path):
    # Bug #13: a typo'd threshold key previously merged in silently while the
    # real threshold stayed at its default with no warning.
    config_path = tmp_path / "config.yaml"
    config_path.write_text("thresholds:\n  high_frequncy_connections: 999\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="Unknown key"):
        load_config(config_path)


def test_load_config_rejects_unknown_top_level_key(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("logging:\n  level: debug\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="Unknown top-level key"):
        load_config(config_path)

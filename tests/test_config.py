from pathlib import Path

from nettrace.config import load_config, package_data_path


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

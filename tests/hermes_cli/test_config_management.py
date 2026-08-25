"""Tests for COM-53 config management additions:

- HERMES_CFG__* env var overrides (apply_env_overrides / get_active_env_overrides)
- `hermes config diff` (diff_config_from_defaults)
- `hermes config validate` CLI wiring reuses the existing validate_config_structure engine
"""

import json

import pytest

from hermes_cli.config import (
    DEFAULT_CONFIG,
    apply_env_overrides,
    diff_config_from_defaults,
    get_active_env_overrides,
    load_config,
    load_config_readonly,
    save_config,
)


class TestGetActiveEnvOverrides:
    def test_none_set(self, monkeypatch):
        monkeypatch.delenv("HERMES_CFG__model", raising=False)
        assert get_active_env_overrides() == {}

    def test_strips_prefix_and_dots_path(self, monkeypatch):
        monkeypatch.setenv("HERMES_CFG__agent__max_turns", "50")
        overrides = get_active_env_overrides()
        assert overrides == {"agent.max_turns": "50"}

    def test_ignores_unrelated_env_vars(self, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", "/tmp/whatever")
        monkeypatch.setenv("HERMES_CFG__model", "foo/bar")
        overrides = get_active_env_overrides()
        assert overrides == {"model": "foo/bar"}


class TestApplyEnvOverrides:
    def test_noop_returns_same_object_when_no_overrides(self, monkeypatch):
        monkeypatch.delenv("HERMES_CFG__model", raising=False)
        cfg = {"model": "x"}
        result = apply_env_overrides(cfg)
        assert result is cfg

    def test_overrides_top_level_scalar(self, monkeypatch):
        monkeypatch.setenv("HERMES_CFG__model", "anthropic/claude-sonnet-4")
        cfg = {"model": "old-model"}
        result = apply_env_overrides(cfg)
        assert result["model"] == "anthropic/claude-sonnet-4"
        assert cfg["model"] == "old-model"  # original not mutated

    def test_overrides_nested_key_with_type_coercion(self, monkeypatch):
        monkeypatch.setenv("HERMES_CFG__agent__max_turns", "50")
        cfg = {"agent": {"max_turns": 90}}
        result = apply_env_overrides(cfg)
        assert result["agent"]["max_turns"] == 50
        assert isinstance(result["agent"]["max_turns"], int)

    def test_bool_coercion(self, monkeypatch):
        monkeypatch.setenv("HERMES_CFG__agent__task_completion_guidance", "false")
        cfg = {"agent": {"task_completion_guidance": True}}
        result = apply_env_overrides(cfg)
        assert result["agent"]["task_completion_guidance"] is False

    def test_creates_missing_nested_path(self, monkeypatch):
        monkeypatch.setenv("HERMES_CFG__brand_new__section__key", "value")
        cfg = {}
        result = apply_env_overrides(cfg)
        assert result["brand_new"]["section"]["key"] == "value"

    def test_list_and_dict_values_json_parsed(self, monkeypatch):
        monkeypatch.setenv("HERMES_CFG__toolsets", '["a", "b"]')
        cfg = {"toolsets": ["hermes-cli"]}
        result = apply_env_overrides(cfg)
        assert result["toolsets"] == ["a", "b"]


class TestLoadConfigAppliesOverrides:
    def test_load_config_applies_override(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        cfg = load_config()
        cfg["model"] = "before-override"
        save_config(cfg)

        monkeypatch.setenv("HERMES_CFG__model", "after-override")
        result = load_config()
        assert result["model"] == "after-override"

    def test_load_config_readonly_applies_override(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv("HERMES_CFG__agent__max_turns", "12")
        result = load_config_readonly()
        assert result["agent"]["max_turns"] == 12

    def test_load_config_readonly_no_override_is_cache_object(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.delenv("HERMES_CFG__model", raising=False)
        # A real config.yaml on disk is required for load_config's mtime/size
        # cache to actually engage (no file => no stable cache signature =>
        # every call rebuilds a fresh dict regardless of env overrides).
        save_config(load_config())
        first = load_config_readonly()
        second = load_config_readonly()
        assert first is second


class TestDiffConfigFromDefaults:
    def test_no_diff_against_defaults_itself(self):
        import copy
        assert diff_config_from_defaults(copy.deepcopy(DEFAULT_CONFIG)) == []

    def test_changed_scalar_detected(self):
        import copy
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["model"] = "custom-model"
        diffs = diff_config_from_defaults(cfg)
        changed = [d for d in diffs if d["key"] == "model"]
        assert len(changed) == 1
        assert changed[0]["status"] == "changed"
        assert changed[0]["current"] == "custom-model"

    def test_added_unknown_key_detected(self):
        import copy
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["totally_new_key"] = "surprise"
        diffs = diff_config_from_defaults(cfg)
        added = [d for d in diffs if d["key"] == "totally_new_key"]
        assert len(added) == 1
        assert added[0]["status"] == "added"

    def test_nested_change_reports_dotted_path(self):
        import copy
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        cfg["agent"] = dict(cfg["agent"])
        cfg["agent"]["max_turns"] = 5
        diffs = diff_config_from_defaults(cfg)
        nested = [d for d in diffs if d["key"] == "agent.max_turns"]
        assert len(nested) == 1
        assert nested[0]["status"] == "changed"
        assert nested[0]["current"] == 5

    def test_defaults_to_load_config(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        diffs = diff_config_from_defaults()
        assert isinstance(diffs, list)

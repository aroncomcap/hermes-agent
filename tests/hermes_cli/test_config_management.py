"""Behavior tests for the COM-53 ``hermes config diff`` addition."""

from hermes_cli.config import (
    DEFAULT_CONFIG,
    diff_config_from_defaults,
    redact_config_diffs,
)


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

    def test_non_string_key_is_reported_without_crashing(self):
        diffs = diff_config_from_defaults({**DEFAULT_CONFIG, 7: "value"})
        assert any(d["key"] == "7" and d["status"] == "added" for d in diffs)


def test_redact_config_diffs_uses_leaf_key_context():
    diffs = [{
        "key": "custom_providers.0.api_key",
        "status": "changed",
        "default": "old-secret-value",
        "current": "new-secret-value",
    }]

    redacted = redact_config_diffs(diffs)

    assert redacted[0]["default"] != "old-secret-value"
    assert redacted[0]["current"] != "new-secret-value"
    assert diffs[0]["current"] == "new-secret-value"

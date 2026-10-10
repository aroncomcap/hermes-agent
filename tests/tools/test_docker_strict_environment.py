import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.environments import docker as docker_env
from tools import terminal_tool


def _workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    (workspace / ".git").mkdir(parents=True)
    return workspace


def test_strict_mount_allowlist_is_canonical_and_closed(tmp_path):
    workspace = _workspace(tmp_path)
    runtime = tmp_path / "runtime"
    runtime.mkdir()

    mounts = docker_env._normalize_strict_mounts([
        {"source": str(runtime), "target": "/runtime", "mode": "ro"},
        {"source": str(workspace), "target": "/workspace", "mode": "rw"},
    ])

    assert mounts == [
        {"source": str(runtime.resolve()), "target": "/runtime", "mode": "ro"},
        {"source": str(workspace.resolve()), "target": "/workspace", "mode": "rw"},
    ]


@pytest.mark.parametrize(
    "entry",
    [
        {"source": "WORKSPACE", "target": "/root", "mode": "ro"},
        {"source": "WORKSPACE", "target": "/workspace", "mode": "invalid"},
        {"source": "WORKSPACE", "target": "/runtime", "mode": "rw"},
    ],
)
def test_strict_mount_allowlist_rejects_non_policy_entries(tmp_path, entry):
    workspace = _workspace(tmp_path)
    entry["source"] = str(workspace)
    with pytest.raises(ValueError):
        docker_env._normalize_strict_mounts([entry])


def test_strict_mount_allowlist_rejects_symlink_source(tmp_path):
    workspace = _workspace(tmp_path)
    link = tmp_path / "linked"
    link.symlink_to(workspace, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        docker_env._normalize_strict_mounts([
            {"source": str(link), "target": "/workspace", "mode": "ro"}
        ])


def test_strict_mode_rejects_raw_args_and_container_reuse():
    with pytest.raises(ValueError, match="docker_extra_args"):
        docker_env.DockerEnvironment(
            image="unused", cwd="/workspace", network=False,
            run_as_host_user=True, persist_across_processes=False,
            extra_args=["--privileged"], strict_mode=True,
        )
    with pytest.raises(ValueError, match="persist_across_processes"):
        docker_env.DockerEnvironment(
            image="unused", cwd="/workspace", network=False,
            run_as_host_user=True, strict_mode=True,
        )


@pytest.mark.parametrize(
    ("security_options", "expected"),
    [(["name=rootless", "name=seccomp,profile=builtin"], True),
     (["name=seccomp,profile=builtin"], False)],
)
def test_rootless_daemon_proof_is_explicit(monkeypatch, security_options, expected):
    monkeypatch.setattr(docker_env, "find_docker", lambda: "/usr/bin/docker")
    monkeypatch.setattr(
        docker_env.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(security_options)
        ),
    )
    assert docker_env._rootless_docker_available() is expected


def test_strict_mode_fails_before_create_on_rootful_daemon(monkeypatch, tmp_path):
    workspace = _workspace(tmp_path)
    monkeypatch.setattr(docker_env, "_resolve_host_user_spec", lambda: "1000:1000")
    monkeypatch.setattr(docker_env, "_cgroup_limits_available", lambda image: True)
    monkeypatch.setattr(docker_env, "_ensure_docker_available", lambda: None)
    monkeypatch.setattr(docker_env, "_rootless_docker_available", lambda: False)

    with pytest.raises(RuntimeError, match="reports name=rootless"):
        docker_env.DockerEnvironment(
            image="unused",
            cwd="/workspace",
            cpu=1,
            memory=512,
            persistent_filesystem=False,
            network=False,
            run_as_host_user=True,
            persist_across_processes=False,
            strict_mode=True,
            strict_mounts=[{
                "source": str(workspace), "target": "/workspace", "mode": "ro",
            }],
        )


def test_strict_config_parses_mounts_and_uses_workspace_cwd(monkeypatch, tmp_path):
    workspace = _workspace(tmp_path)
    mounts = [{"source": str(workspace), "target": "/workspace", "mode": "ro"}]
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    monkeypatch.setenv("TERMINAL_DOCKER_STRICT_MODE", "true")
    monkeypatch.setenv("TERMINAL_DOCKER_STRICT_MOUNTS", json.dumps(mounts))
    monkeypatch.delenv("TERMINAL_CWD", raising=False)

    config = terminal_tool._get_env_config()

    assert config["docker_strict_mode"] is True
    assert config["docker_strict_mounts"] == mounts
    assert config["cwd"] == "/workspace"


def test_strict_config_reaches_docker_environment(monkeypatch):
    captured = {}
    sentinel = object()
    monkeypatch.setattr(
        terminal_tool,
        "_DockerEnvironment",
        lambda **kwargs: captured.update(kwargs) or sentinel,
    )
    monkeypatch.setattr(terminal_tool, "_maybe_reap_docker_orphans", lambda config: None)

    result = terminal_tool._create_environment(
        env_type="docker", image="unused", cwd="/workspace", timeout=10,
        container_config={"docker_strict_mode": True, "docker_strict_mounts": ["sentinel"]},
    )

    assert result is sentinel
    assert captured["strict_mode"] is True
    assert captured["strict_mounts"] == ["sentinel"]


def test_strict_config_is_bridged_by_cli_gateway_and_sibling_tools():
    import ast

    roots = [
        Path("cli.py"), Path("gateway/run.py"), Path("hermes_cli/config.py"),
        Path("tools/terminal_tool.py"), Path("tools/file_tools.py"),
        Path("tools/code_execution_tool.py"),
    ]
    for source in roots:
        tree = ast.parse(source.read_text(encoding="utf-8"))
        keys = {
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        assert "docker_strict_mode" in keys, source
        assert "docker_strict_mounts" in keys, source
def _inspect_payload(tmp_path: Path) -> dict:
    return {
        "Id": "container-id",
        "Image": "sha256:image-id",
        "Mounts": [{
            "Type": "bind",
            "Source": str(tmp_path.resolve()),
            "Destination": "/workspace",
            "RW": False,
        }],
        "HostConfig": {
            "NetworkMode": "none",
            "Privileged": False,
            "ReadonlyRootfs": True,
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "PidMode": "",
            "NanoCpus": 1_000_000_000,
            "Memory": 536_870_912,
            "PidsLimit": 256,
            "Tmpfs": {
                "/tmp": "rw", "/var/tmp": "rw", "/home": "rw",
                "/root": "rw", "/workspace/.git": "rw",
            },
        },
        "Config": {
            "User": "1000:1000",
            "Labels": {"hermes-strict": "1", "hermes-strict-run": "run-id"},
        },
        "State": {"Running": True},
    }


def test_strict_pre_exec_inspection_accepts_exact_identity(monkeypatch, tmp_path):
    payload = _inspect_payload(tmp_path)
    monkeypatch.setattr(
        docker_env.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps([payload])),
    )
    env = docker_env.DockerEnvironment.__new__(docker_env.DockerEnvironment)
    env._docker_exe = "docker"
    env._container_id = "container-id"
    env._strict_created_container_id = "container-id"
    env._strict_expected_image_id = "sha256:image-id"
    env._strict_expected_mounts = [{
        "Source": str(tmp_path.resolve()), "Destination": "/workspace", "RW": False,
    }]

    env._verify_strict_container(require_running=True)


@pytest.mark.parametrize(
    ("section", "key", "value", "failure"),
    [
        ("HostConfig", "NetworkMode", "bridge", "network mode"),
        ("HostConfig", "CapAdd", ["SYS_ADMIN"], "added capabilities"),
        ("Config", "User", "0:0", "non-root user"),
        ("State", "Running", False, "running state"),
    ],
)
def test_strict_pre_exec_inspection_fails_closed(
    monkeypatch, tmp_path, section, key, value, failure
):
    payload = _inspect_payload(tmp_path)
    payload[section][key] = value
    monkeypatch.setattr(
        docker_env.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps([payload])),
    )
    env = docker_env.DockerEnvironment.__new__(docker_env.DockerEnvironment)
    env._docker_exe = "docker"
    env._container_id = "container-id"
    env._strict_created_container_id = "container-id"
    env._strict_expected_image_id = "sha256:image-id"
    env._strict_expected_mounts = [{
        "Source": str(tmp_path.resolve()), "Destination": "/workspace", "RW": False,
    }]

    with pytest.raises(RuntimeError, match=failure):
        env._verify_strict_container(require_running=True)


@pytest.mark.parametrize(
    ("mutation", "failure"),
    [
        (lambda payload: payload.update(Id="different-container"), "container identity"),
        (lambda payload: payload.update(Image="sha256:different-image"), "image digest"),
        (
            lambda payload: payload["Mounts"].append({
                "Type": "bind", "Source": "/etc", "Destination": "/host", "RW": False,
            }),
            "mount allowlist",
        ),
    ],
)
def test_strict_pre_exec_inspection_rejects_identity_and_mount_drift(
    monkeypatch, tmp_path, mutation, failure
):
    payload = _inspect_payload(tmp_path)
    mutation(payload)
    monkeypatch.setattr(
        docker_env.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps([payload])),
    )
    env = docker_env.DockerEnvironment.__new__(docker_env.DockerEnvironment)
    env._docker_exe = "docker"
    env._container_id = "container-id"
    env._strict_created_container_id = "container-id"
    env._strict_expected_image_id = "sha256:image-id"
    env._strict_expected_mounts = [{
        "Source": str(tmp_path.resolve()), "Destination": "/workspace", "RW": False,
    }]

    with pytest.raises(RuntimeError, match=failure):
        env._verify_strict_container(require_running=True)

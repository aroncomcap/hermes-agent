import json
import os
import socket
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.environments import docker as docker_env
from tools.environments.base import BaseEnvironment
from tools import terminal_tool
from scripts import rehearse_strict_docker


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


@pytest.mark.parametrize("layout", ["same", "workspace_parent", "runtime_parent"])
def test_strict_mount_allowlist_rejects_rw_ro_source_overlap(tmp_path, layout):
    workspace = _workspace(tmp_path)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    if layout == "same":
        runtime = workspace
    elif layout == "workspace_parent":
        runtime = workspace / "runtime"
        runtime.mkdir()
    elif layout == "runtime_parent":
        runtime = tmp_path

    with pytest.raises(ValueError, match="may not overlap"):
        docker_env._normalize_strict_mounts([
            {"source": str(workspace), "target": "/workspace", "mode": "rw"},
            {"source": str(runtime), "target": "/runtime", "mode": "ro"},
        ])


class _InitFailureEnvironment(BaseEnvironment):
    def _run_bash(self, *args, **kwargs):
        raise RuntimeError("inspection failed")

    def cleanup(self):
        return None


def test_init_session_can_propagate_for_strict_backends():
    env = _InitFailureEnvironment(cwd="/workspace", timeout=1)
    env._propagate_init_session_errors = True

    with pytest.raises(RuntimeError, match="inspection failed"):
        env.init_session()


def test_init_session_preserves_non_strict_fallback():
    env = _InitFailureEnvironment(cwd="/workspace", timeout=1)

    env.init_session()

    assert env._snapshot_ready is False


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


def test_strict_mount_allowlist_rejects_nested_socket_and_fifo(tmp_path):
    for node_type in ("socket", "fifo"):
        workspace = _workspace(tmp_path / node_type)
        node = workspace / node_type
        if node_type == "socket":
            sock = socket.socket(socket.AF_UNIX)
            sock.bind(str(node))
        else:
            sock = None
            os.mkfifo(node)
        try:
            with pytest.raises(ValueError, match="special node"):
                docker_env._normalize_strict_mounts([{
                    "source": str(workspace), "target": "/workspace", "mode": "ro",
                }])
        finally:
            if sock is not None:
                sock.close()


@pytest.mark.parametrize("mode", [stat.S_IFSOCK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFBLK])
def test_strict_source_tree_rejects_every_special_node_kind(monkeypatch, tmp_path, mode):
    class FakeEntry:
        path = str(tmp_path / "special")

        @staticmethod
        def stat(*, follow_symlinks):
            assert follow_symlinks is False
            return SimpleNamespace(st_mode=mode)

    monkeypatch.setattr(docker_env.os, "scandir", lambda path: [FakeEntry()])
    with pytest.raises(ValueError, match="special node"):
        docker_env._validate_strict_source_tree(tmp_path)


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
    lifecycle_calls = []
    monkeypatch.setattr(docker_env, "_resolve_host_user_spec", lambda: "1000:1000")
    monkeypatch.setattr(
        docker_env,
        "_cgroup_limits_available",
        lambda image: pytest.fail("strict mode must not execute the cgroup probe"),
    )
    monkeypatch.setattr(docker_env, "_ensure_docker_available", lambda: None)
    monkeypatch.setattr(docker_env, "_rootless_docker_available", lambda: False)
    monkeypatch.setattr(
        docker_env.subprocess,
        "run",
        lambda args, **kwargs: lifecycle_calls.append(args)
        or pytest.fail("no docker lifecycle command is allowed before rootless proof"),
    )

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
    assert lifecycle_calls == []


@pytest.mark.parametrize(
    "user_spec", ["1000", "user:1000", "1000:root", "0:1000", "1000:0", "0:0"]
)
def test_strict_mode_requires_exact_non_root_numeric_uid_gid(
    monkeypatch, tmp_path, user_spec
):
    workspace = _workspace(tmp_path)
    monkeypatch.setattr(docker_env, "_resolve_host_user_spec", lambda: user_spec)

    with pytest.raises(RuntimeError, match="numeric host uid:gid|non-root host uid:gid"):
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


def test_rehearsal_cleanup_waits_for_removal():
    class FakeEnvironment:
        def __init__(self, finished: bool):
            self.finished = finished
            self.cleanup_calls = []
            self.wait_calls = []

        def cleanup(self, *, force_remove: bool):
            self.cleanup_calls.append(force_remove)

        def wait_for_cleanup(self, timeout: float):
            self.wait_calls.append(timeout)
            return self.finished

    completed = FakeEnvironment(finished=True)
    rehearse_strict_docker._cleanup_and_wait(completed)
    assert completed.cleanup_calls == [True]
    assert completed.wait_calls == [45]

    timed_out = FakeEnvironment(finished=False)
    with pytest.raises(RuntimeError, match="cleanup timed out"):
        rehearse_strict_docker._cleanup_and_wait(timed_out)
    assert timed_out.cleanup_calls == [True]
    assert timed_out.wait_calls == [45]


def test_rehearsal_mount_dirs_support_remapped_uid_under_private_parent(tmp_path):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    root = parent / "run"
    root.mkdir(mode=0o700)

    workspace, runtime = rehearse_strict_docker._prepare_mount_dirs(root)

    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(root.stat().st_mode) == 0o711
    assert stat.S_IMODE(workspace.stat().st_mode) == 0o777
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o755


def test_strict_config_parses_mounts_and_uses_workspace_cwd(monkeypatch, tmp_path):
    workspace = _workspace(tmp_path)
    mounts = [{"source": str(workspace), "target": "/workspace", "mode": "ro"}]
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    monkeypatch.setenv("TERMINAL_DOCKER_STRICT_MODE", "true")
    monkeypatch.setenv("TERMINAL_DOCKER_STRICT_MOUNTS", json.dumps(mounts))
    monkeypatch.setenv("TERMINAL_DOCKER_STRICT_CONTROL_SOURCE", str(workspace))
    monkeypatch.setenv("TERMINAL_DOCKER_STRICT_CONTROL_LANE", "writer")
    monkeypatch.setenv("TERMINAL_DOCKER_STRICT_CONTROL_MANIFEST_DIGEST", "a" * 64)
    monkeypatch.delenv("TERMINAL_CWD", raising=False)

    config = terminal_tool._get_env_config()

    assert config["docker_strict_mode"] is True
    assert config["docker_strict_mounts"] == mounts
    assert config["docker_strict_control_source"] == str(workspace)
    assert config["docker_strict_control_lane"] == "writer"
    assert config["docker_strict_control_manifest_digest"] == "a" * 64
    assert config["cwd"] == "/workspace"


@pytest.mark.parametrize("value", ["1", "yes", "on", "", "invalid"])
def test_strict_config_rejects_non_closed_boolean(monkeypatch, value):
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    monkeypatch.setenv("TERMINAL_DOCKER_STRICT_MODE", value)
    with pytest.raises(ValueError, match="expected true or false"):
        terminal_tool._get_env_config()


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
        container_config={
            "docker_strict_mode": True, "docker_strict_mounts": ["sentinel"],
            "docker_strict_control_source": "/control", "docker_strict_control_lane": "writer",
            "docker_strict_control_manifest_digest": "a" * 64,
        },
    )

    assert result is sentinel
    assert captured["strict_mode"] is True
    assert captured["strict_mounts"] == ["sentinel"]
    assert captured["strict_control_source"] == "/control"
    assert captured["strict_control_lane"] == "writer"
    assert captured["strict_control_manifest_digest"] == "a" * 64


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
        assert "docker_strict_control_source" in keys, source
        assert "docker_strict_control_lane" in keys, source
        assert "docker_strict_control_manifest_digest" in keys, source
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
        "State": {"Running": True, "Status": "running"},
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
    env._strict_expected_resources = {
        "NanoCpus": 1_000_000_000, "Memory": 536_870_912, "PidsLimit": 256,
    }
    env._strict_expected_user = "1000:1000"

    env._verify_strict_container(require_running=True)


def test_strict_pre_start_requires_created_and_stopped(monkeypatch, tmp_path):
    payload = _inspect_payload(tmp_path)
    payload["State"] = {"Running": False, "Status": "created"}
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
    env._strict_expected_resources = {
        "NanoCpus": 1_000_000_000, "Memory": 536_870_912, "PidsLimit": 256,
    }
    env._strict_expected_user = "1000:1000"
    env._verify_strict_container(require_running=False)

    for state in (
        {"Running": True, "Status": "running"},
        {"Running": False, "Status": "exited"},
    ):
        payload["State"] = state
        with pytest.raises(RuntimeError, match="created state"):
            env._verify_strict_container(require_running=False)


def test_strict_never_starts_or_execs_before_stopped_inspection(monkeypatch, tmp_path):
    workspace = _workspace(tmp_path)
    commands = []
    payload = _inspect_payload(workspace)
    payload["Mounts"][0]["Source"] = str(workspace.resolve())
    payload["State"] = {"Running": True, "Status": "running"}

    monkeypatch.setattr(docker_env, "_resolve_host_user_spec", lambda: "1000:1000")
    monkeypatch.setattr(docker_env, "_ensure_docker_available", lambda: None)
    monkeypatch.setattr(docker_env, "_rootless_docker_available", lambda: True)
    monkeypatch.setattr(docker_env, "find_docker", lambda: "docker")
    monkeypatch.setattr(docker_env, "_image_uses_init_entrypoint", lambda *args: False)
    monkeypatch.setattr(
        docker_env,
        "_cgroup_limits_available",
        lambda image: pytest.fail("strict mode must not execute the cgroup probe"),
    )

    removed = False

    def fake_run(args, **kwargs):
        nonlocal removed
        commands.append(args)
        if args[1] == "create":
            return SimpleNamespace(stdout="container-id\n", returncode=0)
        if args[1:3] == ["image", "inspect"]:
            return SimpleNamespace(stdout="sha256:image-id\n", returncode=0)
        if args[1] == "inspect":
            if removed:
                return SimpleNamespace(stdout="", stderr="No such object", returncode=1)
            return SimpleNamespace(stdout=json.dumps([payload]), returncode=0)
        if args[1] == "stop":
            return SimpleNamespace(stdout="", stderr="", returncode=0)
        if args[1:3] == ["rm", "-f"]:
            removed = True
            return SimpleNamespace(stdout="", stderr="", returncode=0)
        pytest.fail(f"unexpected lifecycle command: {args}")

    monkeypatch.setattr(docker_env.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="created state"):
        docker_env.DockerEnvironment(
            image="strict-image",
            cwd="/workspace",
            cpu=1,
            memory=512,
            network=False,
            run_as_host_user=True,
            persist_across_processes=False,
            strict_mode=True,
            strict_mounts=[{
                "source": str(workspace), "target": "/workspace", "mode": "ro",
            }],
        )

    verbs = [command[1] for command in commands]
    assert "create" in verbs
    assert "inspect" in verbs
    assert not {"run", "start", "exec"}.intersection(verbs)


def test_strict_revalidates_mounts_before_create_and_start(monkeypatch, tmp_path):
    workspace = _workspace(tmp_path)
    events = []
    payload = _inspect_payload(workspace)
    payload["Mounts"][0]["Source"] = str(workspace.resolve())
    payload["State"] = {"Running": False, "Status": "created"}

    monkeypatch.setattr(docker_env, "_resolve_host_user_spec", lambda: "1000:1000")
    monkeypatch.setattr(docker_env, "_ensure_docker_available", lambda: None)
    monkeypatch.setattr(docker_env, "_rootless_docker_available", lambda: True)
    monkeypatch.setattr(docker_env, "find_docker", lambda: "docker")
    monkeypatch.setattr(docker_env, "_image_uses_init_entrypoint", lambda *args: False)
    monkeypatch.setattr(docker_env.DockerEnvironment, "init_session", lambda self: None)
    monkeypatch.setattr(
        docker_env.DockerEnvironment,
        "_revalidate_strict_mounts",
        lambda self: events.append("revalidate"),
    )

    removed = False

    def fake_run(args, **kwargs):
        nonlocal removed
        events.append(args[1])
        if args[1] == "create":
            return SimpleNamespace(stdout="container-id\n", returncode=0)
        if args[1:3] == ["image", "inspect"]:
            return SimpleNamespace(stdout="sha256:image-id\n", returncode=0)
        if args[1] == "inspect":
            if removed:
                return SimpleNamespace(stdout="", stderr="No such container", returncode=1)
            return SimpleNamespace(stdout=json.dumps([payload]), returncode=0)
        if args[1] == "start":
            return SimpleNamespace(stdout="", returncode=0)
        if args[1] == "stop":
            return SimpleNamespace(stdout="", returncode=0)
        if args[1:3] == ["rm", "-f"]:
            removed = True
            return SimpleNamespace(stdout="", stderr="", returncode=0)
        pytest.fail(f"unexpected lifecycle command: {args}")

    monkeypatch.setattr(docker_env.subprocess, "run", fake_run)
    env = docker_env.DockerEnvironment(
        image="strict-image",
        cwd="/workspace",
        cpu=1,
        memory=512,
        network=False,
        run_as_host_user=True,
        persist_across_processes=False,
        strict_mode=True,
        strict_mounts=[{
            "source": str(workspace), "target": "/workspace", "mode": "ro",
        }],
    )

    assert events.index("revalidate") < events.index("create")
    start_index = events.index("start")
    assert events[start_index - 1] == "revalidate"
    assert env._strict_expected_user == "1000:1000"
    env.cleanup()
    assert env._container_id is None


def _strict_cleanup_env() -> docker_env.DockerEnvironment:
    env = docker_env.DockerEnvironment.__new__(docker_env.DockerEnvironment)
    env._docker_exe = "docker"
    env._container_id = "container-id"
    env._strict_mode = True
    env._persistent = False
    env._persist_across_processes = False
    env._workspace_dir = None
    env._home_dir = None
    return env


def test_strict_cleanup_verifies_absence_before_discarding_handle(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args[1])
        if args[1] == "inspect":
            return SimpleNamespace(returncode=1, stdout="", stderr="No such object")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(docker_env.subprocess, "run", fake_run)
    env = _strict_cleanup_env()

    env.cleanup()

    assert calls == ["stop", "rm", "inspect"]
    assert env._container_id is None


@pytest.mark.parametrize("failed_action", ["stop", "rm"])
def test_strict_cleanup_propagates_lifecycle_failures_and_retains_handle(
    monkeypatch, failed_action
):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args[1])
        if args[1] == "inspect":
            return SimpleNamespace(returncode=1, stdout="", stderr="No such container")
        return SimpleNamespace(
            returncode=1 if args[1] == failed_action else 0,
            stdout="",
            stderr="failure",
        )

    monkeypatch.setattr(docker_env.subprocess, "run", fake_run)
    env = _strict_cleanup_env()

    with pytest.raises(RuntimeError, match=f"docker {failed_action} exited 1"):
        env.cleanup()

    assert calls == ["stop", "rm", "inspect"]
    assert env._container_id == "container-id"


def test_strict_cleanup_rejects_unverified_absence_and_retains_handle(monkeypatch):
    def fake_run(args, **kwargs):
        if args[1] == "inspect":
            return SimpleNamespace(returncode=1, stdout="", stderr="daemon unavailable")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(docker_env.subprocess, "run", fake_run)
    env = _strict_cleanup_env()

    with pytest.raises(RuntimeError, match="absence could not be verified"):
        env.cleanup()

    assert env._container_id == "container-id"


def test_strict_cleanup_rejects_container_that_still_exists(monkeypatch):
    def fake_run(args, **kwargs):
        if args[1] == "inspect":
            return SimpleNamespace(returncode=0, stdout="[]", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(docker_env.subprocess, "run", fake_run)
    env = _strict_cleanup_env()

    with pytest.raises(RuntimeError, match="still exists"):
        env.cleanup()

    assert env._container_id == "container-id"


def test_strict_init_failure_triggers_verified_teardown(monkeypatch, tmp_path):
    workspace = _workspace(tmp_path)
    payload = _inspect_payload(workspace)
    payload["Mounts"][0]["Source"] = str(workspace.resolve())
    payload["State"] = {"Running": False, "Status": "created"}
    commands = []
    removed = False

    monkeypatch.setattr(docker_env, "_resolve_host_user_spec", lambda: "1000:1000")
    monkeypatch.setattr(docker_env, "_ensure_docker_available", lambda: None)
    monkeypatch.setattr(docker_env, "_rootless_docker_available", lambda: True)
    monkeypatch.setattr(docker_env, "find_docker", lambda: "docker")
    monkeypatch.setattr(docker_env, "_image_uses_init_entrypoint", lambda *args: False)
    monkeypatch.setattr(
        docker_env.DockerEnvironment,
        "init_session",
        lambda self: (_ for _ in ()).throw(RuntimeError("post-start inspection failed")),
    )

    def fake_run(args, **kwargs):
        nonlocal removed
        commands.append(args[1])
        if args[1] == "create":
            return SimpleNamespace(stdout="container-id\n", stderr="", returncode=0)
        if args[1:3] == ["image", "inspect"]:
            return SimpleNamespace(stdout="sha256:image-id\n", stderr="", returncode=0)
        if args[1] == "inspect":
            if removed:
                return SimpleNamespace(stdout="", stderr="No such object", returncode=1)
            return SimpleNamespace(stdout=json.dumps([payload]), stderr="", returncode=0)
        if args[1] in {"start", "stop"}:
            return SimpleNamespace(stdout="", stderr="", returncode=0)
        if args[1:3] == ["rm", "-f"]:
            removed = True
            return SimpleNamespace(stdout="", stderr="", returncode=0)
        pytest.fail(f"unexpected lifecycle command: {args}")

    monkeypatch.setattr(docker_env.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="post-start inspection failed"):
        docker_env.DockerEnvironment(
            image="strict-image",
            cwd="/workspace",
            cpu=1,
            memory=512,
            network=False,
            run_as_host_user=True,
            persist_across_processes=False,
            strict_mode=True,
            strict_mounts=[{
                "source": str(workspace), "target": "/workspace", "mode": "ro",
            }],
        )

    assert commands[-3:] == ["stop", "rm", "inspect"]


def test_strict_revalidates_mounts_before_every_exec(monkeypatch):
    events = []
    sentinel = object()
    env = docker_env.DockerEnvironment.__new__(docker_env.DockerEnvironment)
    env._docker_exe = "docker"
    env._container_id = "container-id"
    env._strict_mode = True
    env._strict_verified_pre_exec = False
    env._strict_control_volume = "control-volume"
    env._init_env_args = []
    env._revalidate_strict_mounts = lambda: events.append("revalidate")
    env._verify_strict_control_volume = lambda: events.append("control-volume")
    env._verify_strict_control_volume_contents = lambda image=None: events.append("control-content")
    env._verify_strict_container = lambda **kwargs: events.append("inspect")
    monkeypatch.setattr(
        docker_env,
        "_popen_bash",
        lambda *args, **kwargs: events.append("exec") or sentinel,
    )

    assert env._run_bash("true") is sentinel
    assert env._run_bash("true") is sentinel
    assert events == [
        "revalidate", "control-volume", "control-content", "inspect", "exec",
        "revalidate", "control-volume", "control-content", "inspect", "exec",
    ]


def test_strict_mount_race_is_rejected_on_revalidation(tmp_path):
    workspace = _workspace(tmp_path)
    mounts = docker_env._normalize_strict_mounts([{
        "source": str(workspace), "target": "/workspace", "mode": "ro",
    }])
    env = docker_env.DockerEnvironment.__new__(docker_env.DockerEnvironment)
    env._strict_mounts = mounts
    docker_env.DockerEnvironment._revalidate_strict_mounts(env)

    os.mkfifo(workspace / "late-fifo")
    with pytest.raises(RuntimeError, match="special node"):
        docker_env.DockerEnvironment._revalidate_strict_mounts(env)


def test_strict_mount_overlap_is_rejected_on_revalidation(tmp_path):
    workspace = _workspace(tmp_path)
    runtime = workspace / "runtime"
    runtime.mkdir()
    env = docker_env.DockerEnvironment.__new__(docker_env.DockerEnvironment)
    env._strict_mounts = [
        {"source": str(workspace.resolve()), "target": "/workspace", "mode": "rw"},
        {"source": str(runtime.resolve()), "target": "/runtime", "mode": "ro"},
    ]

    with pytest.raises(RuntimeError, match="may not overlap"):
        env._revalidate_strict_mounts()


def test_strict_mount_hardlink_alias_is_rejected_on_revalidation(tmp_path):
    workspace = _workspace(tmp_path)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    workspace_file = workspace / "shared"
    workspace_file.write_text("content", encoding="utf-8")
    os.link(workspace_file, runtime / "shared")
    env = docker_env.DockerEnvironment.__new__(docker_env.DockerEnvironment)
    env._strict_mounts = [
        {"source": str(workspace.resolve()), "target": "/workspace", "mode": "rw"},
        {"source": str(runtime.resolve()), "target": "/runtime", "mode": "ro"},
    ]

    with pytest.raises(RuntimeError, match="share file inodes"):
        env._revalidate_strict_mounts()


@pytest.mark.parametrize(
    ("section", "key", "value", "failure"),
    [
        ("HostConfig", "NetworkMode", "bridge", "network mode"),
        ("HostConfig", "CapAdd", ["SYS_ADMIN"], "added capabilities"),
        ("HostConfig", "Memory", 268_435_456, "resource limits"),
        ("Config", "User", "0:0", "user identity"),
        ("Config", "User", "1001:1000", "user identity"),
        ("Config", "User", "1000:1001", "user identity"),
        ("Config", "User", "root:root", "user identity"),
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
    env._strict_expected_resources = {
        "NanoCpus": 1_000_000_000, "Memory": 536_870_912, "PidsLimit": 256,
    }
    env._strict_expected_user = "1000:1000"

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
    env._strict_expected_resources = {
        "NanoCpus": 1_000_000_000, "Memory": 536_870_912, "PidsLimit": 256,
    }
    env._strict_expected_user = "1000:1000"

    with pytest.raises(RuntimeError, match=failure):
        env._verify_strict_container(require_running=True)

def _volume_env():
    env = docker_env.DockerEnvironment.__new__(docker_env.DockerEnvironment)
    env._docker_exe = "docker"
    env._strict_control_volume = "hermes-strict-writer-test"
    env._strict_control_lane = "writer"
    env._strict_control_bundle = SimpleNamespace(manifest_digest="a" * 64, archive=b"tar")
    env._strict_expected_control_manifest_digest = "a" * 64
    env._strict_helper_label = "helper-label"
    env._strict_expected_resources = {"NanoCpus": 1_000_000_000, "Memory": 536_870_912, "PidsLimit": 256}
    return env


def _volume_payload(**overrides):
    payload = {
        "Name": "hermes-strict-writer-test",
        "Driver": "local",
        "Scope": "local",
        "Options": {},
        "Labels": {
            "hermes-strict-control": "1",
            "hermes-strict-lane": "writer",
            "hermes-strict-manifest": "a" * 64,
        },
    }
    payload.update(overrides)
    return payload


def test_strict_control_volume_rejects_reuse(monkeypatch):
    env = _volume_env()
    monkeypatch.setattr(
        docker_env.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="[]", stderr=""),
    )
    with pytest.raises(RuntimeError, match="reuse is forbidden"):
        env._create_strict_control_volume("image")


def test_strict_control_volume_rejects_driver_options(monkeypatch):
    env = _volume_env()
    monkeypatch.setattr(
        docker_env.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps([_volume_payload(Options={"device": "/host"})]),
            stderr="",
        ),
    )
    with pytest.raises(RuntimeError, match="driver policy changed"):
        env._verify_strict_control_volume()


def _assert_constrained_helper_run(args, *, readonly: bool):
    assert args[:4] == ["docker", "run", "--name", args[3]]
    assert args[3].startswith("hermes-strict-helper-")
    for expected in (
        "--label", "hermes-strict-control-helper=1",
        "--label", "hermes-strict-helper=helper-label",
        "--label", "hermes-strict-lane=writer",
        "--label", f"hermes-strict-manifest={'a' * 64}",
        "--network=none",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--cpus", "1",
        "--memory", "512m",
        "--pids-limit", "256",
        "--user", "0:0",
        "--entrypoint", "tar",
    ):
        assert expected in args
    mount = f"type=volume,src=hermes-strict-writer-test,dst=/runtime{',readonly' if readonly else ''}"
    assert mount in args


def test_strict_control_volume_readback_uses_constrained_helper(monkeypatch):
    env = _volume_env()
    env._image = "candidate-image"
    verified = []
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[:2] == ["docker", "run"]:
            _assert_constrained_helper_run(args, readonly=True)
            assert args[-6:] == ["candidate-image", "-C", "/runtime", "-cf", "-", "."]
            return SimpleNamespace(returncode=0, stdout=b"archive", stderr="")
        if args[:2] == ["docker", "inspect"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="No such container")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(docker_env.subprocess, "run", fake_run)
    monkeypatch.setattr(
        docker_env,
        "verify_control_bundle_archive",
        lambda archive, digest: verified.append((archive, digest)),
    )

    env._verify_strict_control_volume_contents()

    assert verified == [(b"archive", "a" * 64)]
    assert any(call[:3] == ["docker", "rm", "-f"] for call in calls)


def test_strict_control_volume_populate_uses_constrained_helper(monkeypatch):
    env = _volume_env()
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[:3] == ["docker", "volume", "inspect"]:
            if len([c for c in calls if c[:3] == ["docker", "volume", "inspect"]]) == 1:
                return SimpleNamespace(returncode=1, stdout="", stderr="No such volume")
            return SimpleNamespace(returncode=0, stdout=json.dumps([_volume_payload()]), stderr="")
        if args[:2] == ["docker", "run"]:
            _assert_constrained_helper_run(args, readonly=False)
            assert kwargs["input"] == b"tar"
            assert args[-5:] == ["candidate-image", "-xf", "-", "-C", "/runtime"]
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[:2] == ["docker", "inspect"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="No such container")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(docker_env.subprocess, "run", fake_run)
    monkeypatch.setattr(env, "_verify_strict_control_volume_contents", lambda image=None: None)

    env._create_strict_control_volume("candidate-image")

    assert any(call[:2] == ["docker", "run"] for call in calls)


def test_strict_control_helper_timeout_removes_residue(monkeypatch):
    env = _volume_env()
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[:2] == ["docker", "run"]:
            raise docker_env.subprocess.TimeoutExpired(args, timeout=120)
        if args[:3] == ["docker", "rm", "-f"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[:2] == ["docker", "inspect"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="No such container")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(docker_env.subprocess, "run", fake_run)

    with pytest.raises(docker_env.subprocess.TimeoutExpired):
        env._run_strict_control_helper(
            "candidate-image",
            "type=volume,src=hermes-strict-writer-test,dst=/runtime,readonly",
            ["-C", "/runtime", "-cf", "-", "."],
        )

    assert any(call[:3] == ["docker", "rm", "-f"] for call in calls)
    assert any(call[:2] == ["docker", "inspect"] for call in calls)


def test_strict_control_helper_cleanup_fails_closed_on_residue(monkeypatch):
    env = _volume_env()

    def fake_run(args, **kwargs):
        if args[:2] == ["docker", "inspect"]:
            return SimpleNamespace(returncode=0, stdout="[]", stderr="")
        return SimpleNamespace(returncode=0, stdout=b"archive", stderr="")

    monkeypatch.setattr(docker_env.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="helper residue"):
        env._run_strict_control_helper(
            "candidate-image",
            "type=volume,src=hermes-strict-writer-test,dst=/runtime,readonly",
            ["-C", "/runtime", "-cf", "-", "."],
        )


def test_strict_lifecycle_cleans_volume_after_post_create_revalidation_failure(monkeypatch, tmp_path):
    workspace = _workspace(tmp_path)
    control = tmp_path / "control"
    control.mkdir()
    (control / "policy.txt").write_text("trusted", encoding="utf-8")
    digest = docker_env.load_control_bundle(control, workspace).manifest_digest
    calls = []

    monkeypatch.setattr(docker_env, "_resolve_host_user_spec", lambda: "1000:1000")
    monkeypatch.setattr(docker_env, "_ensure_docker_available", lambda: None)
    monkeypatch.setattr(docker_env, "_rootless_docker_available", lambda: True)
    monkeypatch.setattr(docker_env, "_image_uses_init_entrypoint", lambda docker, image: False)
    monkeypatch.setattr(docker_env, "find_docker", lambda: "docker")
    monkeypatch.setattr(
        docker_env.DockerEnvironment,
        "_create_strict_control_volume",
        lambda self, image: calls.append("create-volume") or setattr(self, "_strict_control_volume", "vol"),
    )
    monkeypatch.setattr(
        docker_env.DockerEnvironment,
        "_revalidate_strict_mounts",
        lambda self: (_ for _ in ()).throw(RuntimeError("post-create drift")),
    )
    monkeypatch.setattr(
        docker_env.DockerEnvironment,
        "_teardown_strict_control_volume",
        lambda self: calls.append("teardown-volume") or setattr(self, "_strict_control_volume", ""),
    )
    monkeypatch.setattr(
        docker_env.subprocess,
        "run",
        lambda args, **kwargs: calls.append(args) or SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    with pytest.raises(RuntimeError, match="post-create drift"):
        docker_env.DockerEnvironment(
            image="unused",
            cwd="/workspace",
            cpu=1,
            memory=128,
            network=False,
            run_as_host_user=True,
            persist_across_processes=False,
            strict_mode=True,
            strict_mounts=[{"source": str(workspace), "target": "/workspace", "mode": "rw"}],
            strict_control_source=str(control),
            strict_control_lane="writer",
            strict_control_manifest_digest=digest,
        )

    assert "create-volume" in calls
    assert "teardown-volume" in calls
    assert ["docker", "rm", "-f"] == next(call[:3] for call in calls if isinstance(call, list) and call[:3] == ["docker", "rm", "-f"])


def test_strict_control_source_requires_shared_manifest_match(monkeypatch, tmp_path):
    workspace = _workspace(tmp_path)
    control = tmp_path / "control"
    control.mkdir()
    (control / "policy.txt").write_text("trusted", encoding="utf-8")
    monkeypatch.setattr(docker_env, "_resolve_host_user_spec", lambda: "1000:1000")

    with pytest.raises(ValueError, match="shared digest"):
        docker_env.DockerEnvironment(
            image="unused",
            cwd="/workspace",
            cpu=1,
            memory=128,
            network=False,
            run_as_host_user=True,
            persist_across_processes=False,
            strict_mode=True,
            strict_mounts=[{"source": str(workspace), "target": "/workspace", "mode": "rw"}],
            strict_control_source=str(control),
            strict_control_lane="writer",
            strict_control_manifest_digest="b" * 64,
        )


def test_strict_control_bundle_rejects_caller_runtime_bind(monkeypatch, tmp_path):
    workspace = _workspace(tmp_path)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    control = tmp_path / "control"
    control.mkdir()
    (control / "policy.txt").write_text("trusted", encoding="utf-8")
    monkeypatch.setattr(docker_env, "_resolve_host_user_spec", lambda: "1000:1000")

    with pytest.raises(ValueError, match="forbids caller-supplied /runtime bind"):
        docker_env.DockerEnvironment(
            image="unused",
            cwd="/workspace",
            cpu=1,
            memory=128,
            network=False,
            run_as_host_user=True,
            persist_across_processes=False,
            strict_mode=True,
            strict_mounts=[
                {"source": str(workspace), "target": "/workspace", "mode": "rw"},
                {"source": str(runtime), "target": "/runtime", "mode": "ro"},
            ],
            strict_control_source=str(control),
            strict_control_lane="writer",
            strict_control_manifest_digest="a" * 64,
        )


def test_strict_container_rejects_control_volume_substitution(monkeypatch, tmp_path):
    payload = _inspect_payload(tmp_path)
    payload["Mounts"].append({
        "Type": "volume", "Name": "substitute", "Destination": "/runtime", "RW": False,
    })
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
    env._strict_expected_mounts = [
        {"Type": "bind", "Source": str(tmp_path.resolve()), "Destination": "/workspace", "RW": False},
        {"Type": "volume", "Name": "expected", "Destination": "/runtime", "RW": False},
    ]
    env._strict_expected_resources = {
        "NanoCpus": 1_000_000_000, "Memory": 536_870_912, "PidsLimit": 256,
    }
    env._strict_expected_user = "1000:1000"
    with pytest.raises(RuntimeError, match="mount allowlist"):
        env._verify_strict_container(require_running=True)


def test_strict_control_volume_cleanup_verifies_exact_absence(monkeypatch):
    env = _volume_env()
    calls = []
    responses = iter([
        SimpleNamespace(returncode=0, stdout="", stderr=""),
        SimpleNamespace(returncode=1, stdout="", stderr="Error: No such volume"),
    ])

    def run(args, **kwargs):
        calls.append(args)
        return next(responses)

    monkeypatch.setattr(docker_env.subprocess, "run", run)

    env._teardown_strict_control_volume()

    assert calls == [
        ["docker", "volume", "rm", "hermes-strict-writer-test"],
        ["docker", "volume", "inspect", "hermes-strict-writer-test"],
    ]
    assert env._strict_control_volume == ""

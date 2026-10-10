#!/usr/bin/env python3
"""No-model containment rehearsal for the opt-in strict Docker backend."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.environments.docker import DockerEnvironment, _normalize_strict_mounts
from tools.environments.strict_control_bundle import load_control_bundle


IMAGE = os.environ.get("HERMES_STRICT_REHEARSAL_IMAGE", "debian:12-slim")


def _run(env: DockerEnvironment, command: str) -> None:
    result = env.execute(command)
    if result.get("returncode") != 0:
        raise RuntimeError(result.get("output", "strict rehearsal command failed"))


def _cleanup_and_wait(env: DockerEnvironment) -> None:
    """Remove a rehearsal container before the short-lived process exits."""
    env.cleanup(force_remove=True)
    if not env.wait_for_cleanup(timeout=45):
        raise RuntimeError("strict rehearsal container cleanup timed out")


def _prepare_mount_dirs(root_path: Path) -> tuple[Path, Path]:
    """Create mounts usable by a remapped container UID under a private parent."""
    root_path.chmod(0o711)
    workspace = root_path / "workspace"
    control = root_path / "control"
    workspace.mkdir()
    workspace.chmod(0o777)
    control.mkdir()
    control.chmod(0o755)
    return workspace, control


def main() -> None:
    secret = "strict-provider-secret-must-stay-host-side"
    os.environ["HERMES_FAKE_PROVIDER_SECRET"] = secret
    host_home_sentinel = Path.home() / ".com17822-host-sentinel"
    host_home_sentinel.write_text("host-only", encoding="utf-8")

    try:
        rehearsal_parent = Path.home() / ".cache" / "hermes-strict-rehearsal"
        rehearsal_parent.mkdir(parents=True, exist_ok=True)
        rehearsal_parent.chmod(0o700)
        with tempfile.TemporaryDirectory(
            prefix="hermes-strict-", dir=rehearsal_parent,
        ) as root:
            root_path = Path(root)
            workspace, control = _prepare_mount_dirs(root_path)
            subprocess.run(["git", "init", "-q", str(workspace)], check=True)
            (workspace / "visible.txt").write_text("workspace", encoding="utf-8")
            (control / "control.txt").write_text("control", encoding="utf-8")

            link = root_path / "workspace-link"
            link.symlink_to(workspace, target_is_directory=True)
            try:
                _normalize_strict_mounts([
                    {"source": str(link), "target": "/workspace", "mode": "ro"}
                ])
            except ValueError:
                pass
            else:
                raise RuntimeError("symlink escape negative control was accepted")

            shared_manifest_digest = load_control_bundle(control, workspace).manifest_digest

            common = dict(
                image=IMAGE,
                cwd="/workspace",
                cpu=0.5,
                memory=128,
                disk=0,
                persistent_filesystem=False,
                network=False,
                run_as_host_user=True,
                persist_across_processes=False,
                strict_mode=True,
            )
            writer = DockerEnvironment(
                **common,
                task_id="com17822-writer",
                strict_mounts=[
                    {"source": str(workspace), "target": "/workspace", "mode": "rw"},
                ],
                strict_control_source=str(control),
                strict_control_lane="writer",
                strict_control_manifest_digest=shared_manifest_digest,
            )
            try:
                _run(writer, """
set -eu
test -f /workspace/visible.txt
test -f /runtime/control.txt
test ! -e /workspace/.git/HEAD
test ! -e /var/run/docker.sock
test ! -e /root/.ssh
test ! -e /root/.cache
test ! -e /root/.hermes/skills
test ! -e /home/hermes/.com17822-host-sentinel
test ! -e /home/hermes/work/com-17822-inode-isolated
! grep -a -q strict-provider-secret-must-stay-host-side /proc/1/environ
! awk 'NR > 1 { found=1 } END { exit found ? 0 : 1 }' /proc/net/route
! touch /runtime/must-fail
printf ok > /workspace/writer-proof.txt
""")
                writer_volume = writer._strict_control_volume
                if not writer_volume:
                    raise RuntimeError("writer control volume was not created")
            finally:
                _cleanup_and_wait(writer)

            reviewer = DockerEnvironment(
                **common,
                task_id="com17822-reviewer",
                strict_mounts=[
                    {"source": str(workspace), "target": "/workspace", "mode": "ro"},
                ],
                strict_control_source=str(control),
                strict_control_lane="reviewer",
                strict_control_manifest_digest=shared_manifest_digest,
            )
            try:
                _run(reviewer, """
set -eu
test -f /workspace/writer-proof.txt
test -f /runtime/control.txt
! touch /workspace/reviewer-must-fail
! touch /runtime/reviewer-must-fail
""")
                if not reviewer._strict_control_volume or reviewer._strict_control_volume == writer_volume:
                    raise RuntimeError("writer and reviewer did not receive fresh separate volumes")
            finally:
                _cleanup_and_wait(reviewer)
    finally:
        host_home_sentinel.unlink(missing_ok=True)

    print("strict Docker containment rehearsal: PASS")


if __name__ == "__main__":
    main()

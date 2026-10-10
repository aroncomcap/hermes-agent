#!/usr/bin/env python3
"""No-model containment rehearsal for the opt-in strict Docker backend."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.environments.docker import DockerEnvironment, _normalize_strict_mounts


IMAGE = os.environ.get("HERMES_STRICT_REHEARSAL_IMAGE", "debian:12-slim")


def _run(env: DockerEnvironment, command: str) -> None:
    result = env.execute(command)
    if result.get("returncode") != 0:
        raise RuntimeError(result.get("output", "strict rehearsal command failed"))


def main() -> None:
    secret = "strict-provider-secret-must-stay-host-side"
    os.environ["HERMES_FAKE_PROVIDER_SECRET"] = secret
    host_home_sentinel = Path.home() / ".com17806-host-sentinel"
    host_home_sentinel.write_text("host-only", encoding="utf-8")

    try:
        with tempfile.TemporaryDirectory(prefix="hermes-strict-") as root:
            root_path = Path(root)
            workspace = root_path / "workspace"
            runtime = root_path / "runtime"
            workspace.mkdir()
            runtime.mkdir()
            subprocess.run(["git", "init", "-q", str(workspace)], check=True)
            (workspace / "visible.txt").write_text("workspace", encoding="utf-8")
            (runtime / "control.txt").write_text("control", encoding="utf-8")

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
                task_id="com17806-writer",
                strict_mounts=[
                    {"source": str(workspace), "target": "/workspace", "mode": "rw"},
                    {"source": str(runtime), "target": "/runtime", "mode": "ro"},
                ],
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
test ! -e /home/hermes/.com17806-host-sentinel
test ! -e /home/hermes/wt-com-17806-strict
! grep -a -q strict-provider-secret-must-stay-host-side /proc/1/environ
! awk 'NR > 1 { found=1 } END { exit found ? 0 : 1 }' /proc/net/route
! touch /runtime/must-fail
printf ok > /workspace/writer-proof.txt
""")
            finally:
                writer.cleanup(force_remove=True)

            reviewer = DockerEnvironment(
                **common,
                task_id="com17806-reviewer",
                strict_mounts=[
                    {"source": str(workspace), "target": "/workspace", "mode": "ro"},
                ],
            )
            try:
                _run(reviewer, "test -f /workspace/writer-proof.txt && ! touch /workspace/reviewer-must-fail")
            finally:
                reviewer.cleanup(force_remove=True)
    finally:
        host_home_sentinel.unlink(missing_ok=True)

    print("strict Docker containment rehearsal: PASS")


if __name__ == "__main__":
    main()

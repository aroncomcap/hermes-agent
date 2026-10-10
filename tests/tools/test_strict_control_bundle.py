import io
import json
import os
import tarfile

import pytest

from tools.environments import strict_control_bundle
from tools.environments.strict_control_bundle import (
    load_control_bundle,
    verify_control_bundle_archive,
)


def roots(tmp_path):
    workspace = tmp_path / "workspace"
    control = tmp_path / "control"
    workspace.mkdir()
    control.mkdir()
    return workspace, control


def test_materializes_bytes_and_verifies_manifest(tmp_path):
    workspace, control = roots(tmp_path)
    source = control / "policy.txt"
    source.write_text("original")
    bundle = load_control_bundle(control, workspace)
    source.write_text("changed")
    assert verify_control_bundle_archive(bundle.archive, bundle.manifest_digest)["policy.txt"] == b"original"


def test_materialized_files_are_readable_by_nonroot_runtime_user(tmp_path):
    workspace, control = roots(tmp_path)
    private = control / "private"
    private.mkdir(mode=0o700)
    source = private / "policy.txt"
    source.write_text("policy")
    source.chmod(0o600)
    executable = private / "run.sh"
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o700)

    bundle = load_control_bundle(control, workspace)

    with tarfile.open(fileobj=io.BytesIO(bundle.archive), mode="r:*") as archive:
        assert archive.getmember("private").mode == 0o555
        assert archive.getmember("private/policy.txt").mode == 0o444
        assert archive.getmember("private/run.sh").mode == 0o544
        manifest = json.loads(archive.extractfile(".hermes-control-manifest.json").read())
        assert {entry["path"]: entry["mode"] for entry in manifest["files"]} == {
            "private/policy.txt": 0o444, "private/run.sh": 0o544,
        }


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_rejects_links_and_special_nodes(tmp_path, kind):
    workspace, control = roots(tmp_path)
    item = control / "unsafe"
    if kind == "symlink":
        item.symlink_to(workspace)
    else:
        os.mkfifo(item)
    with pytest.raises(ValueError, match="safely|link or special"):
        load_control_bundle(control, workspace)


def test_rejects_archive_file_mode_drift_from_manifest(tmp_path):
    workspace, control = roots(tmp_path)
    (control / "policy.txt").write_text("policy")
    bundle = load_control_bundle(control, workspace)
    output = io.BytesIO()

    with tarfile.open(fileobj=io.BytesIO(bundle.archive), mode="r:*") as source:
        entries = []
        for member in source.getmembers():
            extracted = source.extractfile(member) if member.isfile() else None
            entries.append((member, extracted.read() if extracted is not None else None))

    with tarfile.open(fileobj=output, mode="w") as archive:
        for member, data in entries:
            if member.name == "policy.txt":
                member.mode = 0o544
            archive.addfile(member, io.BytesIO(data) if data is not None else None)

    with pytest.raises(ValueError, match="mode drift"):
        verify_control_bundle_archive(output.getvalue(), bundle.manifest_digest)


def test_rejects_workspace_hardlink_alias(tmp_path):
    workspace, control = roots(tmp_path)
    original = workspace / "same"
    original.write_text("content")
    os.link(original, control / "alias")
    with pytest.raises(ValueError, match="aliases workspace inode|hardlink aliases"):
        load_control_bundle(control, workspace)


def test_workspace_inode_scan_does_not_follow_swapped_directory(monkeypatch, tmp_path):
    workspace, control = roots(tmp_path)
    (workspace / "nested").mkdir()
    real_open = strict_control_bundle.os.open

    def safe_open(path, flags, *args, **kwargs):
        if path == "nested" and kwargs.get("dir_fd") is not None:
            assert flags & strict_control_bundle.NOFOLLOW
            raise OSError("entry was swapped")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(strict_control_bundle.os, "open", safe_open)
    with pytest.raises(ValueError, match="workspace entry could not be opened safely"):
        load_control_bundle(control, workspace)


def test_rejects_control_source_hardlink_even_outside_workspace(tmp_path):
    workspace, control = roots(tmp_path)
    external = tmp_path / "external"
    external.write_text("content")
    os.link(external, control / "alias")
    with pytest.raises(ValueError, match="hardlink aliases"):
        load_control_bundle(control, workspace)


def test_rejects_credentials_and_receipts(tmp_path):
    workspace, control = roots(tmp_path)
    (control / ".env").write_text("SECRET=value")
    with pytest.raises(ValueError, match="host-only"):
        load_control_bundle(control, workspace)


def test_rejects_manifest_digest_drift(tmp_path):
    workspace, control = roots(tmp_path)
    (control / "policy").write_text("ok")
    bundle = load_control_bundle(control, workspace)
    with pytest.raises(ValueError, match="digest drift"):
        verify_control_bundle_archive(bundle.archive, "0" * 64)


def test_rejects_archive_link(tmp_path):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        link = tarfile.TarInfo("escape")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../etc/passwd"
        archive.addfile(link)
    with pytest.raises(ValueError, match="link or special"):
        verify_control_bundle_archive(output.getvalue(), "0" * 64)

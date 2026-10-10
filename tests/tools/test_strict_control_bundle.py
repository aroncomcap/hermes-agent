import io
import os
import tarfile

import pytest

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


def test_rejects_workspace_hardlink_alias(tmp_path):
    workspace, control = roots(tmp_path)
    original = workspace / "same"
    original.write_text("content")
    os.link(original, control / "alias")
    with pytest.raises(ValueError, match="aliases workspace inode"):
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

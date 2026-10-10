"""Trusted byte materialization for strict Docker control bundles."""
import hashlib
import io
import json
import os
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MANIFEST = ".hermes-control-manifest.json"
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
FORBIDDEN = {".env", "credentials", "credentials.json", "receipts", "secrets"}


@dataclass(frozen=True)
class ControlBundle:
    archive: bytes
    manifest_digest: str
    file_count: int


def _path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe control bundle path: {name}")
    if {part.lower() for part in path.parts} & FORBIDDEN or path.suffix.lower() in {".key", ".pem"}:
        raise ValueError(f"credentials and receipts must remain host-only: {path}")
    return path


def _inodes(root: Path) -> set[tuple[int, int]]:
    found = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                if stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode):
                    found.add((info.st_dev, info.st_ino))
    return found


def _read_tree(root: Path, forbidden: set[tuple[int, int]]):
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    pending = [(root_fd, None)]
    directories, files = [], {}
    while pending:
        directory_fd, prefix = pending.pop()
        try:
            for name in sorted(os.listdir(directory_fd)):
                relative = PurePosixPath(name) if prefix is None else prefix / name
                _path(str(relative))
                try:
                    child_fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | NOFOLLOW, dir_fd=directory_fd)
                except OSError as exc:
                    raise ValueError(f"control source entry could not be opened safely: {relative}") from exc
                keep = False
                try:
                    before = os.fstat(child_fd)
                    if (before.st_dev, before.st_ino) in forbidden:
                        raise ValueError(f"control source aliases workspace inode: {relative}")
                    if stat.S_ISDIR(before.st_mode):
                        directories.append(str(relative))
                        pending.append((child_fd, relative))
                        keep = True
                    elif stat.S_ISREG(before.st_mode):
                        data = b""
                        while chunk := os.read(child_fd, 1024 * 1024):
                            data += chunk
                        after = os.fstat(child_fd)
                        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                            raise ValueError(f"control source changed while being read: {relative}")
                        files[str(relative)] = (data, stat.S_IMODE(before.st_mode))
                    else:
                        raise ValueError(f"control source contains link or special node: {relative}")
                finally:
                    if not keep:
                        os.close(child_fd)
        finally:
            os.close(directory_fd)
    return sorted(directories), files


def load_control_bundle(source: str | Path, workspace: str | Path) -> ControlBundle:
    source = Path(source)
    if not stat.S_ISDIR(os.lstat(source).st_mode):
        raise ValueError("control source must be a real directory")
    directories, files = _read_tree(source, _inodes(Path(workspace)))
    manifest = {"version": 1, "files": [
        {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "mode": mode & 0o777}
        for path, (data, mode) in sorted(files.items())
    ]}
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for directory in directories:
            info = tarfile.TarInfo(directory)
            info.type, info.mode = tarfile.DIRTYPE, 0o555
            archive.addfile(info)
        for path, (data, mode) in sorted(files.items()):
            info = tarfile.TarInfo(path)
            info.size, info.mode = len(data), mode & 0o555
            archive.addfile(info, io.BytesIO(data))
        info = tarfile.TarInfo(MANIFEST)
        info.size, info.mode = len(manifest_bytes), 0o444
        archive.addfile(info, io.BytesIO(manifest_bytes))
    bundle = ControlBundle(output.getvalue(), digest, len(files))
    verify_control_bundle_archive(bundle.archive, digest)
    return bundle


def verify_control_bundle_archive(archive_bytes: bytes, expected_digest: str) -> dict[str, bytes]:
    files, manifest_bytes, seen = {}, None, set()
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as archive:
            for member in archive.getmembers():
                raw_name = member.name.rstrip("/")
                while raw_name.startswith("./"):
                    raw_name = raw_name[2:]
                if raw_name in {"", "."} and member.isdir():
                    continue
                name = str(_path(raw_name))
                if name in seen:
                    raise ValueError(f"duplicate control bundle path: {name}")
                seen.add(name)
                if member.isdir():
                    if member.mode & 0o222:
                        raise ValueError(f"control bundle entry is writable: {name}")
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    raise ValueError(f"control bundle contains link or special node: {name}")
                if member.mode & 0o222:
                    raise ValueError(f"control bundle entry is writable: {name}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError(f"control bundle file unreadable: {name}")
                data = extracted.read()
                if name == MANIFEST:
                    manifest_bytes = data
                else:
                    files[name] = data
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("control bundle archive is invalid") from exc
    if manifest_bytes is None or hashlib.sha256(manifest_bytes).hexdigest() != expected_digest:
        raise ValueError("control bundle manifest digest drift")
    try:
        entries = json.loads(manifest_bytes)["files"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError("control bundle manifest is invalid") from exc
    expected_paths = set()
    for entry in entries:
        name = str(_path(entry["path"]))
        if name in expected_paths:
            raise ValueError(f"duplicate control bundle manifest path: {name}")
        expected_paths.add(name)
        data = files.get(name)
        if data is None or len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"control bundle content digest drift: {name}")
    if set(files) != expected_paths:
        raise ValueError("control bundle contents do not match manifest")
    return files

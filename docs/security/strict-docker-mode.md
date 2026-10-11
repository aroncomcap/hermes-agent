# Strict Docker tool mode

Strict mode is an opt-in containment profile for Hermes file, terminal, and
code-execution tools. It is intended for disposable worktrees and read-only
review snapshots. Provider credentials remain in the host Hermes process and
are never forwarded or mounted into the tool container.

## Design: inode-separated runtime bundle

Strict mode does not trust path-only separation between writable workspace files
and runtime controls. When `docker_strict_control_source` is set, Hermes reads
that source tree as trusted bytes on the host, rejects unsafe entries, writes a
manifested tar archive, verifies the archive, then materializes it into a fresh
private Docker volume named for this run/lane. The container receives only that
fresh volume mounted read-only at `/runtime`; caller-supplied `/runtime` binds
are rejected. The writable `/workspace` bind therefore has no path, mount, or
inode alias to the immutable controls.

The bundle source may contain only regular files and directories. Hermes rejects
absolute paths, `.`/`..`, symlinks, hardlinks, FIFOs, sockets, device nodes,
credential/receipt paths, `.key`/`.pem` material, duplicate archive paths,
writable archive entries, manifest digest drift, and content digest drift.
Every source file must have link count 1, and every source file inode is checked
against the workspace inode set before it is copied. Runtime controls such as
prompts, reviewer configuration, credentials metadata, receipts, and policy
inputs should be placed in the control source only when they are non-secret and
safe to expose read-only to the sandbox; live provider secrets stay host-only.

The strict lifecycle is fail-closed:

1. Resolve and validate the exact non-root numeric host UID:GID with
   `os.getuid():os.getgid()`; UID 0 or GID 0 is rejected.
2. Require rootless Docker, `cwd=/workspace`, `docker_network=false`, positive
   CPU and memory limits, no persistent filesystem, no cross-process reuse, no
   forwarded env, no explicit env, no raw Docker args, no automatic CWD mount,
   and an image without a privileged init entrypoint.
3. Canonicalize strict mounts and reject identical sources, nested sources,
   symlinked sources, non-policy targets, writable `/runtime`, and hardlink
   inode intersections between writable and read-only source trees. Record the
   validated device/inode identity for every bind root.
4. Build and verify the immutable control archive, create a new local Docker
   volume with lane/manifest labels, populate it with `tar`, chmod it read-only,
   and read it back through a read-only mount to verify the manifest again.
5. Create, but do not start, the container with a read-only root filesystem,
   network disabled, all capabilities dropped, no-new-privileges, exact UID:GID,
   exact resource limits, tmpfs masks for `/tmp`, `/var/tmp`, `/home`, `/root`,
   and `/workspace/.git`, and only the expected `/workspace` bind plus optional
   `/runtime` volume.
6. Inspect the stopped container before start and reject image, mount, resource,
   network, user, capability, label, state, or identity drift. Any failure tears
   down the container and control volume and proves their absence.
7. Start only the trusted image's inert `sleep` command, then use the trusted
   image's `/usr/bin/stat` to prove that every bind root's actual device/inode
   matches the validated host source before any agent command or workspace
   content executes. This catches a parent-directory exchange while the daemon
   resolves the bind. Re-prove the mounted identities, original pathnames,
   source-tree safety, cross-tree inode isolation, control volume identity, and
   live container inspection before every exec.
8. Cleanup is idempotent and verified: strict containers are stopped, removed,
   inspected for absence, and only then is the handle discarded; strict control
   volumes are removed and inspected for absence. Failed teardown raises and
   retains the handle so callers do not mistake partial cleanup for success.

Rollback is configuration-only: disable `docker_strict_mode` or remove the
strict-control keys to return to the regular Docker backend. No production
activation or COM-17788 rollout should happen until the rehearsal below passes
on the target host and design review approves the exact branch.

## Activate

Use a rootless Docker daemon, a non-root host account, and an image that can run
directly as that UID/GID (not the bundled s6-init image). The workspace must be
a disposable clone with a real `.git` directory; `.git` is masked inside the
container.

Writer lane:

```yaml
terminal:
  backend: docker
  cwd: /workspace
  docker_image: debian:12-slim
  container_cpu: 1
  container_memory: 2048
  container_persistent: false
  docker_network: false
  docker_run_as_host_user: true
  docker_persist_across_processes: false
  docker_strict_mode: true
  docker_strict_mounts:
    - source: /absolute/path/to/disposable-clone
      target: /workspace
      mode: rw
  docker_strict_control_source: /absolute/path/to/control-source
  docker_strict_control_lane: writer
```

Reviewer lane uses the same control source but makes `/workspace` read-only and
sets `docker_strict_control_lane: reviewer`.

Without `docker_strict_control_source`, strict mode still accepts an explicit
read-only `/runtime` bind for legacy tests, but the inode-separated control
bundle path is required for approval/production use.

## Negative controls

The test suite and rehearsal cover:

- identical, nested, and symlinked source paths
- adversarial parent-directory exchange while Docker resolves a bind source
- hardlink aliases within the control source and across workspace/runtime trees
- late TOCTOU changes after initial verification and before later execs
- sockets, FIFOs, block devices, char devices, symlinks, and archive links
- caller-supplied `/runtime` bind when a control source is configured
- control-volume reuse, driver-option substitution, and mount substitution
- network, UID:GID, capability, read-only-rootfs, resource, label, state, and
  image drift
- teardown success, teardown failure, unverified absence, and idempotent cleanup

## Rehearse without a model

On a Linux host with rootless Docker and `debian:12-slim` available:

```bash
python scripts/rehearse_strict_docker.py
```

The rehearsal uses a fake host-side provider secret and checks workspace-only
visibility, host-home and repository isolation, `/proc/1/environ`, credential,
skill, cache and Docker-socket absence, symlink rejection, no network routes,
the `.git` mask, a read-only runtime control volume, writer workspace writes,
reviewer workspace read-only behavior, and separate per-lane runtime volumes.
It does not invoke a model or provider.

# Strict Docker tool mode

Strict mode is an opt-in containment profile for Hermes file, terminal, and
code-execution tools. It is intended for disposable worktrees and read-only
review snapshots. Provider credentials remain in the host Hermes process and
are never forwarded or mounted into the tool container.

## Activate

Use a rootless Docker daemon, a non-root host account, and an image that can run directly as that UID/GID
(not the bundled s6-init image). The workspace must be a disposable clone with
a real `.git` directory; `.git` is masked inside the container.

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
    - source: /absolute/path/to/review-control
      target: /runtime
      mode: ro
```

For a reviewer, set the `/workspace` mount to `ro`. `/runtime`, when present,
is always read-only. Strict mode rejects ordinary Docker volumes, forwarded or
explicit environment variables, raw Docker arguments, automatic CWD mounts,
persistent filesystems, container reuse, networking, root users, missing
resource limits, symlinked sources, and mount targets outside `/workspace` and
`/runtime`. Activation also fails unless `docker info` reports the daemon's
`name=rootless` security option.

Before the first tool command, Hermes creates a fresh stopped container and
checks its immutable image ID, exact bind mounts, network namespace, non-root
user, capabilities, no-new-privileges, read-only root filesystem, tmpfs masks,
resource limits, run label, and container identity. Any mismatch aborts before
execution and removes the container.

## Rehearse without a model

On a Linux host with Docker and `debian:12-slim` available:

```bash
python scripts/rehearse_strict_docker.py
```

The rehearsal uses a fake host-side provider secret and checks workspace-only
visibility, host-home and repository isolation, `/proc/1/environ`, credential,
skill, cache and Docker-socket absence, symlink rejection, no network routes,
the `.git` mask, a read-only runtime, and a separate read-only reviewer
snapshot. It does not invoke a model or provider.

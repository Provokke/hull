<div align="center">

# hull

`hull` is a small container runtime for Linux, written in Rust. It works like a very small Docker and calls the kernel directly through `libc`/`nix`, with no container libraries. It provides:

![License](https://img.shields.io/badge/LICENSE-MIT-blue?style=for-the-badge)  ![Language](https://img.shields.io/badge/RUST-dea584?style=for-the-badge&logo=rust&logoColor=white)

Refer to [LICENSE](LICENSE) for the legal bits.

</div>

## 🏗️ Architecture

```text
 hull run (supervisor, host)                     clone(NEWPID|NEWNS|NEWUTS|NEWIPC|NEWNET)
 ──────────────────────────                      ───────────────────────────────────────
 resolve image -> <root>/images/layers/<sha>/rootfs
 mkdir containers/<id>/{upper,work,merged}
 create cgroup (v1: memory/cpu/pids dirs,        ┌─ hull-init  (PID 1 in new pid ns)
                v2: /sys/fs/cgroup/hull/<id>)    │   block on "go" pipe
 clone() ───────────────────────────────────────►│
 write pid to cgroup.procs                       │
 [--net bridge] veth -> child netns, ip/route    │
 "go" ──────────────────────────────────────────►│   sethostname, lo up
                                                 │   mount / rprivate (nothing leaks to host)
                                                 │   overlay lower=image upper,work -> merged
                                                 │   bind volumes (symlink-escape checked)
                                                 │   /proc, /proc/sys ro, /sys ro, /dev tmpfs
                                                 │   pivot_root(".", ".") + umount old root
 read status pipe until EOF ◄── "mode:pivot_root"│      (fallback: chroot)
   (CLOEXEC: EOF == command exec'd)              │   fork ─► command: drop caps, no_new_privs,
 state.json: running, pid                        │           seccomp, execvp   (PID 2)
 sigwait loop: forward TERM/INT/HUP/... ────────►│   sigwait loop: reap every child (orphans
 waitpid(init)                                   │     too), forward signals to command
 read cgroup stats (oom_kill, throttling)        └─ exit(command status | 128+signal)
 rmdir cgroup, delete veth, state: exited(code)
```

On-disk layout. Everything lives under `$HULL_ROOT`, which defaults to
`/var/lib/hull`:

```text
images/blobs/sha256/<hex>         the original tarball; the digest is the sha256 of these bytes
images/layers/<hex>/rootfs/       unpacked layer (the overlay lowerdir)
images/layers/<hex>/meta.json
images/refs.json                  name -> digest
containers/<id>/state.json        container state (see `hull inspect`)
containers/<id>/{upper,work}/     per-container writable layer
containers/<id>/merged/           mount point, used only inside the container's mount namespace
containers/<id>/container.log     stdout and stderr
```

Source modules (`src/`):

- `cli.rs`: argument parsing.
- `util.rs`: size and cpu parsing, ids, atomic writes.
- `state.rs`: container state JSON.
- `image.rs`: the content-addressed store and the busybox rootfs builder.
- `cgroup.rs`: v1/v2 detection, the plan of cgroup writes, applying it, stats.
- `security.rs`: capabilities, `no_new_privs`, seccomp-BPF.
- `container.rs`: run, init, exec, stop, rm.
- `net.rs`: bridge, veth and NAT.

## 🚀 Quick start

```sh
cargo build --release
sudo ./target/release/hull pull alpine        # falls back to a busybox rootfs if the CDN is unreachable
sudo ./target/release/hull run --hostname demo --memory 64m --cpus 0.5 --pids 32 alpine sh -c 'hostname; ps'
sudo ./target/release/hull run -d --name web -v /srv/data:/data alpine sleep 600
sudo ./target/release/hull exec web ps
sudo ./target/release/hull ps
sudo ./target/release/hull stop web && sudo ./target/release/hull logs web && sudo ./target/release/hull rm web
sudo ./target/release/hull import rootfs.tar.gz myimage
```

Other options:

- `-e K=V` sets an environment variable.
- `--net bridge` turns on bridge networking.
- `--no-seccomp` turns off the seccomp filter.
- `-v host:ctr:ro` mounts a volume read-only.
- `HULL_FORCE_CHROOT=1` forces the chroot fallback.

This is real output from the sandbox the project was built in:

```text
$ hull pull alpine
hull: downloading https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
hull: alpine CDN unreachable (curl: (22) The requested URL returned error: 403); falling back to busybox-static rootfs
alpine sha256:25a519e1efcbda3b85df75a9bf1a1af9cce59bcfc77001dfa10a67ad2a40adc8

$ hull run --hostname demo --memory 64m --pids 32 bench sh -c 'hostname; cat /proc/1/comm; ps; grep CapBnd /proc/self/status'
demo
hull-init
PID   USER     COMMAND
    1 root     {hull-init} target/release/hull run --hostname demo ...
    2 root     sh -c hostname; cat /proc/1/comm; ps; ...
    5 root     {ps} sh -c hostname; ...
CapBnd:	00000000a00405fb

$ hull ps
CONTAINER ID  IMAGE       COMMAND                   CREATED     STATUS        PID       NAME
542144f9a7dd  alpine      sh -c trap "echo got ...  0s ago      running       23984     web
$ hull exec web sh -c 'ps; exit 3'; echo exec=$?
PID   USER     COMMAND
    1 root     {hull-init} target/debug/hull run -d --name web alpine sh -c trap "echo got TERM; exit 42" ...
    2 root     sh -c trap "echo got TERM; exit 42" TERM; echo started; while :; do sleep 0.1; done
    4 root     sh -c ps; exit 3
    5 root     {ps} sh -c ps; exit 3
exec=3
$ hull stop web; hull logs web; hull ps -a | grep web
started
got TERM
542144f9a7dd  alpine      sh -c trap "echo got ...  0s ago      exited (42)             web
```

## 🧪 Testing

```sh
cargo test                               # 35 unit/property tests; the 19 privileged tests print SKIPPED and return
sudo HULL_PRIVILEGED_TESTS=1 cargo test  # full suite: 35 unit + 19 privileged end-to-end tests
make lint                                # cargo fmt --check, cargo clippy --all-targets -D warnings
```

Note that the Rust test harness has no runtime "skip". When
`HULL_PRIVILEGED_TESTS` is not set, or the tests are not run as root, each
privileged test prints `SKIPPED <name>: ...` and returns, so the harness
counts it as passed.

**Unit and property tests (35).** These run without root and cover:

- size and cpu parsing, including proptest round-trips and no-panic fuzzing;
- CLI parsing, including proptest no-panic;
- state JSON round-trip, listing and id-prefix/name resolution, and detecting
  pid reuse ("dead");
- the image store: identical tarballs dedupe, gzip input, refusal of `../`
  path traversal, and a reproducible busybox tarball;
- cgroup v1 and v2 limit plans, and mountinfo/stat parsing;
- the seccomp BPF program, checked by a small BPF interpreter inside the
  test: every denied syscall gives EPERM, other syscalls are allowed, and a
  foreign architecture is killed;
- the capability mask, IP allocation and veth name lengths.

**Privileged end-to-end tests (19, in `tests/privileged.rs`).** These run the
real binary with state under `/var/lib/hull-itest`. Each line gives the
behaviour proved and how the test proves it:

| Test | What it proves |
|---|---|
| `runs_as_pid1_in_fresh_pid_namespace` | `/proc/1/comm` is `hull-init`, the command runs as pid 2, and at most 4 processes are visible |
| `cannot_see_host_processes` | the test's own host pid and a host `sleep` are invisible |
| `hostname_is_isolated` | `--hostname` works, the host hostname is unchanged, and the default hostname is the container id |
| `filesystem_isolation_and_copy_on_write` | host files are invisible. Writes and deletes (as a whiteout char device) land in `upper/` while the image layer stays untouched, and a new container sees the pristine image |
| `volumes_rw_and_ro` | bind volumes work, and a write to a `:ro` volume fails |
| `memory_limit_oom_kills_hog` | a 256 MiB `dd` under `--memory 32m` exits with 137 and `oom_kill` ≥ 1 is recorded. A control run under 256m succeeds |
| `pids_limit_contains_fork_bomb` | with `--pids 12`, a 60-process bomb leaves ≤ 12 processes. The control run reaches ≥ 60 |
| `cpu_limit_is_observable` | a busy loop under `--cpus 0.2` uses ≤ 80 ticks in 2 s (the theoretical value is 40), and `nr_throttled` > 0 |
| `exec_into_running_container` | exec sees the container's hostname and PID 1, its writes are shared, exit code 3 propagates, `rm` without `-f` refuses, and exec fails after rm |
| `exit_codes_propagate` | exit codes 7 and 0 pass through, `kill -9 $$` gives 137, and a missing binary gives 127 |
| `stop_forwards_sigterm_through_init` | a trap in the command sees SIGTERM and the exit code is 42 |
| `stop_escalates_to_sigkill` | a command that ignores TERM is killed after `-t 1` and exits with 137 |
| `foreground_run_forwards_signals` | SIGINT sent to `hull run` reaches the command's trap, and the exit code is 9 |
| `init_reaps_orphaned_zombies` | five orphaned children are reaped, with no `Z` state |
| `privileges_are_dropped` | CapBnd and CapEff equal the keep mask, NoNewPrivs is 1 and Seccomp is 2. mount, sethostname, writes to /sys and /proc/sys, and mknod all fail. The /dev nodes exist, and `--no-seccomp` shows 0 |
| `chroot_fallback_works_and_is_reported` | the state records `chroot` when forced and `pivot_root` by default |
| `image_store_is_content_addressed` | pulling twice gives the same digest, and re-importing the blob gives the same digest |
| `bridge_network_reaches_host` | the container IP is on `eth0`, `wget` reaches a TCP server on the host bridge from the container's IP, the veth is removed on rm, and the default mode has only `lo` |
| `no_leftovers_after_many_runs` | after 5 runs with all limits, no cgroups, mounts or container directories remain |

Every test that exercises a lifecycle also checks the host after the container
exits: the container must not appear in the host's `/proc/mounts`, and its
cgroup directories must be gone. In the sandbox the full privileged suite
passed 4 times in a row (19/19 each time, about 2.2 s per run with 4 test
threads).

## ⏱️ Benchmarks

`sudo scripts/bench.sh 50` runs the release build on a shared, busy 4-core VM
with cgroup v1. Numbers are milliseconds per operation (ms/op):

```text
baseline: fork+exec /bin/true              1.12 ms/op  (50 ops)
hull run (all namespaces) true            20.33 ms/op  (50 ops)
hull run + cgroup limits true              7.95 ms/op  (50 ops)
hull exec (setns) true                     3.31 ms/op  (50 ops)
hull stop (SIGTERM via init)              23.29 ms/op  (1 ops)
hull rm                                    2.47 ms/op  (101 ops)
```

The first `run` row was consistently slower than the second over two runs of
the script. It is the first loop in the script, and I did not investigate
why. Treat it as noise or an ordering effect, not as evidence that limits make
startup faster. The real cost of a run is roughly 8 to 20 ms.

## ⚠️ Honest limits

- **cgroup v2:** the code is implemented and unit-tested (plan and stats
  parsing), but this sandbox only has v1. The v2 path has not been run
  end-to-end here. The CI workflow includes a privileged job intended to
  exercise it on v2 runners, but that job has not been run.
- **Alpine download:** the Alpine CDN was blocked (403) in this sandbox, so
  `pull alpine` fell back to a busybox-static rootfs registered under that
  name. The `SOURCE` column in `hull images` shows this.
- **Not implemented:**
  - user namespaces (containers run as real root, with reduced capabilities);
  - a devices cgroup (CAP_MKNOD is dropped instead);
  - an OCI image/registry protocol, multi-layer images, and TTY/interactive
    `-it`;
  - `logs -f`.
- **Foreground output:** stdout and stderr are tee'd through pipes, so the
  command does not see a TTY.
- **The supervisor is per-container:** if it is SIGKILLed, `PR_SET_PDEATHSIG`
  kills the container too. `stop` and `rm` then mark the state as exited and
  clean up.
- **chroot fallback is weaker:** unlike `pivot_root`, it does not detach the
  host root from the mount namespace.
- **Bridge networking needs host tools:** it shells out to `ip` and
  `iptables`; there is no netlink implementation. Addresses come from
  10.88.0.0/16 and are allocated by scanning running containers, so races are
  possible.
- **Seccomp:** the filter is a short denylist, not Docker's allowlist.

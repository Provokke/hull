//! Container lifecycle: create -> clone into new namespaces -> init (PID 1)
//! -> exec user command; plus exec (setns), stop, rm.
//!
//! ```text
//!  hull run (supervisor)                  clone(NEWPID|NEWNS|NEWUTS|NEWIPC|NEWNET)
//!  ─────────────────────                  ───────────────────────────────────────
//!  create cgroup                           ┌── hull-init (PID 1 in the new pid ns)
//!  clone() ───────────────────────────────►│   wait for "go"
//!  add child pid to cgroup                 │   hostname, make / rprivate
//!  [bridge] veth into child netns          │   overlay(lower=image, upper, work)
//!  write "go" ────────────────────────────►│   volumes, /proc, /sys (ro), /dev
//!  read status pipe until EOF ◄────────────│   pivot_root (fallback: chroot)
//!  state = running                         │   fork ──► drop caps, no_new_privs,
//!  sigwait loop: forward signals,          │            seccomp, execvp(cmd)
//!    wait for init to exit                 │   sigwait loop: reap zombies,
//!  record exit code + cgroup stats         │     forward signals to cmd
//!  remove cgroup                           └── exit(cmd status)
//! ```

use crate::cgroup::Cgroup;
use crate::cli::{NetMode, RunOpts, Volume};
use crate::image::Store;
use crate::net;
use crate::security;
use crate::state::{self, ContainerState, FinalStats, Limits, NetInfo, Status};
use crate::util::{now_secs, pid_alive, proc_start_time, random_id};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::CloneFlags;
use nix::sys::signal::{kill, SigSet, SigmaskHow, Signal};
use nix::sys::stat::{makedev, mknod, Mode, SFlag};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{chdir, chroot, fork, pivot_root, sethostname, ForkResult, Pid};
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Signals the supervisor and init forward to their child.
const FORWARDED: &[Signal] = &[
    Signal::SIGTERM,
    Signal::SIGINT,
    Signal::SIGHUP,
    Signal::SIGQUIT,
    Signal::SIGUSR1,
    Signal::SIGUSR2,
    Signal::SIGWINCH,
];

fn signal_set() -> SigSet {
    let mut s = SigSet::empty();
    s.add(Signal::SIGCHLD);
    for sig in FORWARDED {
        s.add(*sig);
    }
    s
}

fn block_signals() {
    let _ = nix::sys::signal::sigprocmask(SigmaskHow::SIG_BLOCK, Some(&signal_set()), None);
}

fn unblock_all_signals() {
    let _ = nix::sys::signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None);
}

pub fn status_code(ws: WaitStatus) -> Option<i32> {
    match ws {
        WaitStatus::Exited(_, c) => Some(c),
        WaitStatus::Signaled(_, s, _) => Some(128 + s as i32),
        _ => None,
    }
}

fn pipe() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

fn close(fd: RawFd) {
    unsafe { libc::close(fd) };
}

fn write_fd(fd: RawFd, msg: &str) {
    let b = msg.as_bytes();
    unsafe { libc::write(fd, b.as_ptr() as *const _, b.len()) };
}

fn read_all_fd(fd: RawFd) -> String {
    let mut f = unsafe { fs::File::from_raw_fd(fd) };
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    s
}

/// Mark every fd >= 3 close-on-exec so nothing leaks into the container.
fn cloexec_from_3() {
    if let Ok(rd) = fs::read_dir("/proc/self/fd") {
        let fds: Vec<i32> = rd
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse().ok())
            .collect();
        for fd in fds {
            if fd >= 3 {
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            }
        }
    }
}

/// Everything the cloned child needs, captured before clone.
#[derive(Clone)]
struct ChildCfg {
    hostname: String,
    lower: PathBuf,
    upper: PathBuf,
    work: PathBuf,
    merged: PathBuf,
    volumes: Vec<Volume>,
    cmd: Vec<String>,
    env: Vec<(String, String)>,
    seccomp: bool,
    force_chroot: bool,
}

fn ctx<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
}

/// Resolve `inside` (an absolute container path) under `root` and make sure
/// the result, after following symlinks already present in the image, stays
/// inside `root`. Creates the target (dir or file) if missing.
fn safe_target(root: &Path, inside: &str, is_dir: bool) -> Result<PathBuf, String> {
    let rel = inside.trim_start_matches('/');
    let t = root.join(rel);
    if is_dir {
        ctx(fs::create_dir_all(&t), &format!("mkdir {}", t.display()))?;
    } else {
        if let Some(p) = t.parent() {
            ctx(fs::create_dir_all(p), "mkdir")?;
        }
        if !t.exists() {
            ctx(fs::File::create(&t), "create mount target")?;
        }
    }
    let canon = ctx(t.canonicalize(), "canonicalize")?;
    let croot = ctx(root.canonicalize(), "canonicalize root")?;
    if !canon.starts_with(&croot) {
        return Err(format!("volume target {inside} escapes the container root"));
    }
    Ok(canon)
}

fn bring_up_loopback() {
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            return;
        }
        let mut req: libc::ifreq = std::mem::zeroed();
        for (i, b) in b"lo\0".iter().enumerate() {
            req.ifr_name[i] = *b as libc::c_char;
        }
        if libc::ioctl(s, libc::SIOCGIFFLAGS, &mut req) == 0 {
            req.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            libc::ioctl(s, libc::SIOCSIFFLAGS, &req);
        }
        libc::close(s);
    }
}

fn setup_dev(dev: &Path) -> Result<(), String> {
    let nosuid = MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME;
    ctx(
        mount(
            Some("tmpfs"),
            dev,
            Some("tmpfs"),
            nosuid,
            Some("mode=755,size=65536k"),
        ),
        "mount /dev tmpfs",
    )?;
    for (name, major, minor) in [
        ("null", 1, 3),
        ("zero", 1, 5),
        ("full", 1, 7),
        ("random", 1, 8),
        ("urandom", 1, 9),
        ("tty", 5, 0),
    ] {
        let p = dev.join(name);
        ctx(
            mknod(
                &p,
                SFlag::S_IFCHR,
                Mode::from_bits_truncate(0o666),
                makedev(major, minor),
            ),
            &format!("mknod /dev/{name}"),
        )?;
        let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o666));
    }
    for (l, t) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
        ("ptmx", "pts/ptmx"),
    ] {
        ctx(
            std::os::unix::fs::symlink(t, dev.join(l)),
            "symlink in /dev",
        )?;
    }
    let pts = dev.join("pts");
    ctx(fs::create_dir(&pts), "mkdir /dev/pts")?;
    let _ = mount(
        Some("devpts"),
        &pts,
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620"),
    );
    let shm = dev.join("shm");
    ctx(fs::create_dir(&shm), "mkdir /dev/shm")?;
    ctx(
        mount(
            Some("shm"),
            &shm,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            Some("mode=1777,size=65536k"),
        ),
        "mount /dev/shm",
    )?;
    Ok(())
}

/// Build the container root filesystem inside the new mount namespace and
/// switch to it. Returns "pivot_root" or "chroot".
fn setup_rootfs(c: &ChildCfg) -> Result<&'static str, String> {
    // Never let any of our mounts propagate back to the host.
    ctx(
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        ),
        "make / rprivate",
    )?;
    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        c.lower.display(),
        c.upper.display(),
        c.work.display()
    );
    ctx(
        mount(
            Some("overlay"),
            &c.merged,
            Some("overlay"),
            MsFlags::empty(),
            Some(opts.as_str()),
        ),
        "mount overlay",
    )?;
    let m = &c.merged;
    for v in &c.volumes {
        let host = Path::new(&v.host);
        let md = fs::metadata(host).map_err(|e| format!("volume {}: {e}", v.host))?;
        let target = safe_target(m, &v.container, md.is_dir())?;
        ctx(
            mount(
                Some(host),
                &target,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            ),
            &format!("bind {}", v.host),
        )?;
        if v.readonly {
            ctx(
                mount(
                    None::<&str>,
                    &target,
                    None::<&str>,
                    MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                    None::<&str>,
                ),
                "remount volume ro",
            )?;
        }
    }
    let proc_ = safe_target(m, "/proc", true)?;
    let hard = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    ctx(
        mount(Some("proc"), &proc_, Some("proc"), hard, None::<&str>),
        "mount /proc",
    )?;
    let sys = safe_target(m, "/sys", true)?;
    ctx(
        mount(
            Some("sysfs"),
            &sys,
            Some("sysfs"),
            hard | MsFlags::MS_RDONLY,
            None::<&str>,
        ),
        "mount /sys",
    )?;
    let dev = safe_target(m, "/dev", true)?;
    setup_dev(&dev)?;
    // /proc hardening: read-only /proc/sys, mask a few dangerous files.
    let psys = proc_.join("sys");
    if mount(
        Some(&psys),
        &psys,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .is_ok()
    {
        let _ = mount(
            None::<&str>,
            &psys,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        );
    }
    for f in ["sysrq-trigger", "kcore"] {
        let p = proc_.join(f);
        if p.exists() {
            let _ = mount(
                Some(&dev.join("null")),
                &p,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            );
        }
    }

    ctx(chdir(m), "chdir rootfs")?;
    if !c.force_chroot && pivot_root(".", ".").is_ok() {
        // The old root is now stacked on top of the new one; detach it.
        ctx(umount2(".", MntFlags::MNT_DETACH), "detach old root")?;
        ctx(chdir("/"), "chdir /")?;
        Ok("pivot_root")
    } else {
        ctx(chroot("."), "chroot")?;
        ctx(chdir("/"), "chdir /")?;
        Ok("chroot")
    }
}

/// Apply in-container restrictions and exec. Only returns on failure.
fn exec_command(cmd: &[String], env: &[(String, String)], seccomp: bool) -> String {
    unblock_all_signals();
    for sig in FORWARDED.iter().chain([Signal::SIGPIPE].iter()) {
        unsafe {
            let _ = nix::sys::signal::signal(*sig, nix::sys::signal::SigHandler::SigDfl);
        }
    }
    for (k, _) in std::env::vars_os() {
        std::env::remove_var(k);
    }
    std::env::set_var(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    std::env::set_var("HOME", "/root");
    std::env::set_var("TERM", "xterm");
    for (k, v) in env {
        std::env::set_var(k, v);
    }
    if let Ok(h) = nix::unistd::gethostname() {
        std::env::set_var("HOSTNAME", h);
    }
    cloexec_from_3();
    if let Err(e) = security::drop_capabilities() {
        return format!("drop capabilities: {e}");
    }
    if let Err(e) = security::set_no_new_privs() {
        return format!("no_new_privs: {e}");
    }
    if seccomp {
        if let Err(e) = security::install_seccomp() {
            return format!("seccomp: {e}");
        }
    }
    let args: Vec<CString> = match cmd.iter().map(|a| CString::new(a.as_str())).collect() {
        Ok(a) => a,
        Err(_) => return "command contains NUL byte".into(),
    };
    match nix::unistd::execvp(&args[0], &args) {
        Err(e) => format!("exec {}: {e}", cmd[0]),
        Ok(_) => unreachable!(),
    }
}

/// Body of the cloned child: becomes PID 1 of the container.
fn child_main(c: &ChildCfg, go_r: RawFd, status_w: RawFd, stdio: Option<(RawFd, RawFd)>) -> isize {
    // Die with the supervisor.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };
    let mut b = [0u8; 1];
    if unsafe { libc::read(go_r, b.as_mut_ptr() as *mut _, 1) } != 1 {
        return 1;
    }
    close(go_r);
    if let Some((o, e)) = stdio {
        unsafe {
            libc::dup2(o, 1);
            libc::dup2(e, 2);
        }
        close(o);
        close(e);
    }
    let name = CString::new("hull-init").unwrap();
    unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0) };

    if let Err(e) = sethostname(&c.hostname) {
        write_fd(status_w, &format!("err:sethostname: {e}\n"));
        return 1;
    }
    bring_up_loopback();
    let mode = match setup_rootfs(c) {
        Ok(m) => m,
        Err(e) => {
            write_fd(status_w, &format!("err:{e}\n"));
            return 1;
        }
    };
    write_fd(status_w, &format!("mode:{mode}\n"));

    // PID 1: fork the real command, then reap and forward until it exits.
    let main = match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let err = exec_command(&c.cmd, &c.env, c.seccomp);
            write_fd(status_w, &format!("err:{err}\n"));
            unsafe { libc::_exit(127) };
        }
        Ok(ForkResult::Parent { child }) => child,
        Err(e) => {
            write_fd(status_w, &format!("err:fork: {e}\n"));
            return 1;
        }
    };
    close(status_w);
    init_loop(main) as isize
}

/// Reap every child (orphans get reparented to us) and forward signals to
/// the main process. Returns the main process' exit status.
fn init_loop(main: Pid) -> i32 {
    let set = signal_set();
    loop {
        let sig = match set.wait() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if sig == Signal::SIGCHLD {
            loop {
                match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) | Err(_) => break,
                    Ok(ws) => {
                        if ws.pid() == Some(main) {
                            if let Some(code) = status_code(ws) {
                                return code;
                            }
                        }
                    }
                }
            }
        } else {
            let _ = kill(main, sig);
        }
    }
}

/// Wait for `child` while forwarding signals to `target` (usually the same pid).
fn supervise_wait(child: Pid, target: Pid) -> i32 {
    let set = signal_set();
    loop {
        // A SIGCHLD may have been consumed before we started waiting.
        if let Ok(ws) = waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            if let Some(code) = status_code(ws) {
                return code;
            }
        } else {
            return 255;
        }
        match set.wait() {
            Ok(Signal::SIGCHLD) | Err(_) => {}
            Ok(sig) => {
                let _ = kill(target, sig);
            }
        }
    }
}

fn hostname_for(o: &RunOpts, id: &str) -> String {
    o.hostname.clone().unwrap_or_else(|| id.to_string())
}

/// `hull run`: returns the process exit code for the CLI.
pub fn run(root: &Path, o: &RunOpts) -> Result<i32, String> {
    let store = Store::new(root);
    let digest = store.resolve(&o.image)?;
    let lower = store.rootfs(&digest);
    if let Some(n) = &o.name {
        if state::list(root)
            .iter()
            .any(|s| s.name.as_deref() == Some(n.as_str()))
        {
            return Err(format!("container name '{n}' already in use"));
        }
    }
    for v in &o.volumes {
        if !Path::new(&v.host).exists() {
            return Err(format!("volume source {} does not exist", v.host));
        }
    }
    let id = random_id();
    let dir = state::container_dir(root, &id);
    for d in ["upper", "work", "merged"] {
        ctx(fs::create_dir_all(dir.join(d)), "create container dir")?;
    }
    let st = ContainerState {
        id: id.clone(),
        name: o.name.clone(),
        image: o.image.clone(),
        image_digest: digest,
        cmd: o.cmd.clone(),
        hostname: hostname_for(o, &id),
        status: Status::Created,
        pid: None,
        pid_start_time: None,
        supervisor_pid: None,
        exit_code: None,
        created_at: now_secs(),
        started_at: None,
        finished_at: None,
        limits: Limits {
            memory: o.memory,
            cpus_milli: o.cpus_milli,
            pids: o.pids,
        },
        rootfs_mode: None,
        cgroup_version: None,
        cgroup_paths: vec![],
        volumes: o.volumes.clone(),
        net: NetInfo {
            mode: o.net,
            ip: None,
            host_veth: None,
        },
        stats: FinalStats::default(),
        error: None,
    };
    ctx(st.save(root), "save state")?;
    let cfg = ChildCfg {
        hostname: st.hostname.clone(),
        lower,
        upper: dir.join("upper"),
        work: dir.join("work"),
        merged: dir.join("merged"),
        volumes: o.volumes.clone(),
        cmd: o.cmd.clone(),
        env: o.env.clone(),
        seccomp: o.seccomp,
        force_chroot: std::env::var_os("HULL_FORCE_CHROOT").is_some_and(|v| v == "1"),
    };
    let log = dir.join("container.log");

    if !o.detach {
        return Ok(supervise(root, st, cfg, &log, None, true));
    }
    let (r, w) = ctx(pipe(), "pipe")?;
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            close(r);
            unsafe { libc::setsid() };
            let logf = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o640)
                .open(&log);
            let devnull = fs::File::open("/dev/null");
            if let (Ok(l), Ok(n)) = (logf, devnull) {
                use std::os::fd::AsRawFd;
                unsafe {
                    libc::dup2(n.as_raw_fd(), 0);
                    libc::dup2(l.as_raw_fd(), 1);
                    libc::dup2(l.as_raw_fd(), 2);
                }
            }
            let code = supervise(root, st, cfg, &log, Some(w), false);
            unsafe { libc::_exit(code) };
        }
        Ok(ForkResult::Parent { .. }) => {
            close(w);
            let msg = read_all_fd(r);
            if msg.starts_with("ok") {
                println!("{id}");
                Ok(0)
            } else {
                Err(msg.trim_start_matches("err:").trim().to_string())
            }
        }
        Err(e) => Err(format!("fork: {e}")),
    }
}

fn tee_thread(fd: RawFd, to_stderr: bool, log: Option<fs::File>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut src = unsafe { fs::File::from_raw_fd(fd) };
        let mut log = log;
        let mut buf = [0u8; 8192];
        loop {
            let n = match src.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if to_stderr {
                let _ = io::stderr().write_all(&buf[..n]);
            } else {
                let mut out = io::stdout();
                let _ = out.write_all(&buf[..n]);
                let _ = out.flush();
            }
            if let Some(l) = log.as_mut() {
                let _ = l.write_all(&buf[..n]);
            }
        }
    })
}

/// Create cgroup + namespaces, start the container and wait for it.
fn supervise(
    root: &Path,
    mut st: ContainerState,
    cfg: ChildCfg,
    log: &Path,
    notify: Option<RawFd>,
    tee: bool,
) -> i32 {
    let fail = |st: &mut ContainerState, msg: String, notify: Option<RawFd>| -> i32 {
        // Like docker: 127 when the command cannot be executed, else 125.
        let code = if msg.starts_with("exec ") { 127 } else { 125 };
        st.status = Status::Exited;
        st.exit_code = Some(code);
        st.finished_at = Some(now_secs());
        st.error = Some(msg.clone());
        let _ = st.save(root);
        match notify {
            Some(n) => write_fd(n, &format!("err:{msg}")),
            None => eprintln!("hull: {msg}"),
        }
        code
    };
    st.supervisor_pid = Some(std::process::id() as i32);
    let cg = match Cgroup::create(&st.id, &st.limits) {
        Ok(c) => c,
        Err(e) => return fail(&mut st, format!("cgroup setup: {e}"), notify),
    };
    st.cgroup_version = Some(cg.version.as_str().to_string());
    st.cgroup_paths = cg.paths();

    block_signals();
    let pipes = (|| -> io::Result<_> {
        let go = pipe()?;
        let status = pipe()?;
        let stdio = if tee { Some((pipe()?, pipe()?)) } else { None };
        Ok((go, status, stdio))
    })();
    let ((go_r, go_w), (status_r, status_w), stdio) = match pipes {
        Ok(p) => p,
        Err(e) => {
            cg.destroy();
            return fail(&mut st, format!("pipe: {e}"), notify);
        }
    };
    let child_stdio = stdio.map(|((_, ow), (_, ew))| (ow, ew));
    let parent_reads = stdio.map(|((or, _), (er, _))| (or, er));

    let mut stack = vec![0u8; 1 << 20];
    let flags = CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWNET;
    let child_cfg = cfg.clone();
    let cb = Box::new(move || {
        if let Some(n) = notify {
            close(n);
        }
        close(go_w);
        close(status_r);
        if let Some((or, er)) = parent_reads {
            close(or);
            close(er);
        }
        child_main(&child_cfg, go_r, status_w, child_stdio)
    });
    let pid = match unsafe { nix::sched::clone(cb, &mut stack, flags, Some(libc::SIGCHLD)) } {
        Ok(p) => p,
        Err(e) => {
            cg.destroy();
            return fail(&mut st, format!("clone: {e}"), notify);
        }
    };
    close(go_r);
    close(status_w);
    if let Some((ow, ew)) = child_stdio {
        close(ow);
        close(ew);
    }

    let abort = |st: &mut ContainerState, msg: String, cg: &Cgroup| -> i32 {
        let _ = kill(pid, Signal::SIGKILL);
        let _ = waitpid(pid, None);
        cg.destroy();
        if st.net.host_veth.is_some() {
            net::teardown(st);
        }
        fail(st, msg, notify)
    };

    if let Err(e) = cg.add(pid.as_raw()) {
        close(go_w);
        return abort(&mut st, format!("cgroup attach: {e}"), &cg);
    }
    if st.net.mode == NetMode::Bridge {
        match net::setup(root, &st.id, pid.as_raw()) {
            Ok((ip, veth)) => {
                st.net.ip = Some(ip);
                st.net.host_veth = Some(veth);
                let _ = st.save(root);
            }
            Err(e) => {
                close(go_w);
                return abort(&mut st, format!("network setup: {e}"), &cg);
            }
        }
    }
    write_fd(go_w, "g");
    close(go_w);

    let status = read_all_fd(status_r);
    let mut err = None;
    for line in status.lines() {
        if let Some(m) = line.strip_prefix("mode:") {
            st.rootfs_mode = Some(m.to_string());
        } else if let Some(e) = line.strip_prefix("err:") {
            err = Some(e.to_string());
        }
    }
    if let Some(e) = err {
        return abort(&mut st, e, &cg);
    }
    st.status = Status::Running;
    st.pid = Some(pid.as_raw());
    st.pid_start_time = proc_start_time(pid.as_raw());
    st.started_at = Some(now_secs());
    let _ = st.save(root);
    if let Some(n) = notify {
        write_fd(n, "ok");
        close(n);
    }

    let tees = parent_reads.map(|(or, er)| {
        let open_log = || {
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log)
                .ok()
        };
        (
            tee_thread(or, false, open_log()),
            tee_thread(er, true, open_log()),
        )
    });
    let code = supervise_wait(pid, pid);
    if let Some((a, b)) = tees {
        let _ = a.join();
        let _ = b.join();
    }
    st.stats = cg.stats();
    cg.destroy();
    if st.net.host_veth.is_some() {
        net::teardown(&st);
    }
    st.status = Status::Exited;
    st.exit_code = Some(code);
    st.finished_at = Some(now_secs());
    let _ = st.save(root);
    code
}

/// `hull exec`: join a running container's namespaces and cgroup.
pub fn exec(root: &Path, r: &str, cmd: &[String]) -> Result<i32, String> {
    let st = state::resolve(root, r)?;
    if !st.is_alive() {
        return Err(format!("container {} is not running", st.id));
    }
    let pid = st.pid.unwrap();
    let open = |p: String| ctx(fs::File::open(&p), &p);
    let nss: Vec<(fs::File, CloneFlags)> = vec![
        (
            open(format!("/proc/{pid}/ns/ipc"))?,
            CloneFlags::CLONE_NEWIPC,
        ),
        (
            open(format!("/proc/{pid}/ns/uts"))?,
            CloneFlags::CLONE_NEWUTS,
        ),
        (
            open(format!("/proc/{pid}/ns/net"))?,
            CloneFlags::CLONE_NEWNET,
        ),
        (
            open(format!("/proc/{pid}/ns/pid"))?,
            CloneFlags::CLONE_NEWPID,
        ),
        (
            open(format!("/proc/{pid}/ns/mnt"))?,
            CloneFlags::CLONE_NEWNS,
        ),
    ];
    let rootfd = open(format!("/proc/{pid}/root"))?;
    // Re-check that the pid was not recycled while we opened the files.
    if !pid_alive(pid, st.pid_start_time) {
        return Err("container exited".into());
    }
    let cg = Cgroup::from_paths(
        st.cgroup_version.as_deref().unwrap_or("v1"),
        &st.cgroup_paths,
    );
    ctx(cg.add(std::process::id() as i32), "join cgroup")?;
    block_signals();
    for (f, flag) in &nss {
        ctx(nix::sched::setns(f, *flag), "setns")?;
    }
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::fchdir(rootfd.as_raw_fd());
            }
            if chroot(".").is_err() || chdir("/").is_err() {
                eprintln!("hull: cannot enter container root");
                unsafe { libc::_exit(126) };
            }
            let err = exec_command(cmd, &[], true);
            eprintln!("hull: {err}");
            unsafe { libc::_exit(127) };
        }
        Ok(ForkResult::Parent { child }) => Ok(supervise_wait(child, child)),
        Err(e) => Err(format!("fork: {e}")),
    }
}

/// `hull stop`: SIGTERM to init (which forwards it), SIGKILL after timeout.
pub fn stop(root: &Path, r: &str, timeout: u64) -> Result<(), String> {
    let st = state::resolve(root, r)?;
    if !st.is_alive() {
        finalize_if_orphaned(root, &st.id);
        return Ok(());
    }
    let pid = Pid::from_raw(st.pid.unwrap());
    let _ = kill(pid, Signal::SIGTERM);
    let deadline = Instant::now() + Duration::from_secs(timeout);
    while pid_alive(pid.as_raw(), st.pid_start_time) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    if pid_alive(pid.as_raw(), st.pid_start_time) {
        let _ = kill(pid, Signal::SIGKILL);
    }
    // Wait for the supervisor to record the exit and clean up.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(s) = ContainerState::load(root, &st.id) {
            if s.status == Status::Exited {
                return Ok(());
            }
            if !s.supervisor_pid.is_some_and(|p| pid_alive(p, None)) {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    finalize_if_orphaned(root, &st.id);
    Ok(())
}

/// If a container is marked running but its init and supervisor are gone
/// (e.g. the supervisor was SIGKILLed), clean up its cgroup and mark it exited.
fn finalize_if_orphaned(root: &Path, id: &str) {
    let Ok(mut s) = ContainerState::load(root, id) else {
        return;
    };
    if s.status != Status::Running || s.is_alive() {
        return;
    }
    if s.supervisor_pid.is_some_and(|p| pid_alive(p, None)) {
        return;
    }
    let cg = Cgroup::from_paths(s.cgroup_version.as_deref().unwrap_or("v1"), &s.cgroup_paths);
    cg.destroy();
    if s.net.host_veth.is_some() {
        net::teardown(&s);
    }
    s.status = Status::Exited;
    s.finished_at = Some(now_secs());
    s.error = Some("supervisor exited before recording the exit status".into());
    let _ = s.save(root);
}

/// Mount points under `dir` visible in the current mount namespace.
pub fn mounts_under(dir: &Path) -> Vec<String> {
    let d = dir.display().to_string();
    fs::read_to_string("/proc/self/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1).map(String::from))
        .filter(|m| m.starts_with(&d))
        .collect()
}

/// `hull rm`.
pub fn rm(root: &Path, r: &str, force: bool) -> Result<String, String> {
    let st = state::resolve(root, r)?;
    if st.is_alive() {
        if !force {
            return Err(format!("container {} is running (use rm -f)", st.id));
        }
        stop(root, &st.id, 0)?;
    }
    finalize_if_orphaned(root, &st.id);
    let st = ContainerState::load(root, &st.id).map_err(|e| e.to_string())?;
    if st.status == Status::Running && st.supervisor_pid.is_some_and(|p| pid_alive(p, None)) {
        return Err(format!("container {} is still being torn down", st.id));
    }
    let dir = st.dir(root);
    for m in mounts_under(&dir).iter().rev() {
        let _ = umount2(m.as_str(), MntFlags::MNT_DETACH);
    }
    let cg = Cgroup::from_paths(
        st.cgroup_version.as_deref().unwrap_or("v1"),
        &st.cgroup_paths,
    );
    cg.destroy();
    ctx(fs::remove_dir_all(&dir), "remove container dir")?;
    Ok(st.id)
}

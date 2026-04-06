//! Privilege reduction applied right before exec'ing user code:
//! capability bounding-set drop, capset, no_new_privs and a seccomp filter.

use std::io;

// Capability numbers (linux/capability.h).
pub const CAP_CHOWN: u32 = 0;
pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_FOWNER: u32 = 3;
pub const CAP_FSETID: u32 = 4;
pub const CAP_KILL: u32 = 5;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_SETPCAP: u32 = 8;
pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_SYS_CHROOT: u32 = 18;
pub const CAP_AUDIT_WRITE: u32 = 29;
pub const CAP_SETFCAP: u32 = 31;

/// Capabilities a container process keeps. Notably absent: SYS_ADMIN,
/// NET_ADMIN, NET_RAW, SYS_MODULE, SYS_PTRACE, SYS_TIME, MKNOD, SYS_BOOT...
pub const KEEP_CAPS: &[u32] = &[
    CAP_CHOWN,
    CAP_DAC_OVERRIDE,
    CAP_FOWNER,
    CAP_FSETID,
    CAP_KILL,
    CAP_SETGID,
    CAP_SETUID,
    CAP_SETPCAP,
    CAP_NET_BIND_SERVICE,
    CAP_SYS_CHROOT,
    CAP_AUDIT_WRITE,
    CAP_SETFCAP,
];

/// Bitmask of KEEP_CAPS (as it appears in /proc/<pid>/status CapBnd).
pub fn keep_mask() -> u64 {
    KEEP_CAPS.iter().fold(0u64, |m, c| m | (1u64 << c))
}

fn last_cap() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(40)
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Drop every capability not in KEEP_CAPS from the bounding set and from the
/// effective/permitted/inheritable sets of the calling thread.
pub fn drop_capabilities() -> io::Result<()> {
    let keep = keep_mask();
    for cap in 0..=last_cap() {
        if keep & (1u64 << cap) == 0 {
            let r = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
            if r != 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EINVAL) {
                    return Err(e);
                }
            }
        }
    }
    // Clear ambient set too.
    unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    let hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let lo = keep as u32;
    let hi = (keep >> 32) as u32;
    let data = [
        CapData {
            effective: lo,
            permitted: lo,
            inheritable: lo,
        },
        CapData {
            effective: hi,
            permitted: hi,
            inheritable: hi,
        },
    ];
    let r = unsafe { libc::syscall(libc::SYS_capset, &hdr as *const CapHeader, data.as_ptr()) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn set_no_new_privs() -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Syscalls denied with EPERM by the default seccomp profile.
pub fn denied_syscalls() -> Vec<(&'static str, i64)> {
    vec![
        ("kexec_load", libc::SYS_kexec_load),
        ("init_module", libc::SYS_init_module),
        ("finit_module", libc::SYS_finit_module),
        ("delete_module", libc::SYS_delete_module),
        ("keyctl", libc::SYS_keyctl),
        ("add_key", libc::SYS_add_key),
        ("request_key", libc::SYS_request_key),
        ("bpf", libc::SYS_bpf),
        ("perf_event_open", libc::SYS_perf_event_open),
        ("userfaultfd", libc::SYS_userfaultfd),
        ("open_by_handle_at", libc::SYS_open_by_handle_at),
        ("unshare", libc::SYS_unshare),
        ("setns", libc::SYS_setns),
        ("mount", libc::SYS_mount),
        ("umount2", libc::SYS_umount2),
        ("pivot_root", libc::SYS_pivot_root),
        ("swapon", libc::SYS_swapon),
        ("swapoff", libc::SYS_swapoff),
        ("reboot", libc::SYS_reboot),
        ("settimeofday", libc::SYS_settimeofday),
        ("clock_settime", libc::SYS_clock_settime),
        ("ptrace", libc::SYS_ptrace),
        ("process_vm_writev", libc::SYS_process_vm_writev),
    ]
}

#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH: u32 = 0xc000_00b7;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

fn stmt(code: u32, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

/// Build the classic-BPF program:
/// ```text
///   ld arch; jeq AUDIT_ARCH ? next : kill
///   ld nr; for each denied: jeq nr ? errno(EPERM) : next
///   ret allow
/// ```
pub fn build_filter(denied: &[i64]) -> Vec<libc::sock_filter> {
    let ld_w_abs = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    let jeq = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
    let ret = libc::BPF_RET | libc::BPF_K;
    let mut f = vec![
        stmt(ld_w_abs, 4), // seccomp_data.arch
        jump(jeq, AUDIT_ARCH, 1, 0),
        stmt(ret, SECCOMP_RET_KILL_PROCESS),
        stmt(ld_w_abs, 0), // seccomp_data.nr
    ];
    let n = denied.len();
    for (i, nr) in denied.iter().enumerate() {
        // on match jump to the ERRNO return which sits after the remaining
        // compares and the ALLOW return.
        let remaining = (n - i - 1) as u8;
        f.push(jump(jeq, *nr as u32, remaining + 1, 0));
    }
    f.push(stmt(ret, SECCOMP_RET_ALLOW));
    f.push(stmt(ret, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    f
}

pub fn install_seccomp() -> io::Result<()> {
    let nrs: Vec<i64> = denied_syscalls().iter().map(|(_, n)| *n).collect();
    let filter = build_filter(&nrs);
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    let r = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as libc::c_ulong,
            &prog as *const libc::sock_fprog as libc::c_ulong,
            0,
            0,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_contents() {
        let m = keep_mask();
        assert_ne!(m & (1 << CAP_KILL), 0);
        assert_eq!(m & (1 << 21), 0, "CAP_SYS_ADMIN must be dropped");
        assert_eq!(m & (1 << 12), 0, "CAP_NET_ADMIN must be dropped");
        assert_eq!(m & (1 << 13), 0, "CAP_NET_RAW must be dropped");
        assert_eq!(m & (1 << 27), 0, "CAP_MKNOD must be dropped");
        assert_eq!(m, 0xa80425fb & !(1 << 27) & !(1 << 13));
    }

    /// Interpret the BPF program in-process for a given (arch, nr).
    fn run(f: &[libc::sock_filter], arch: u32, nr: u32) -> u32 {
        let mut pc = 0usize;
        let mut acc = 0u32;
        loop {
            let i = f[pc];
            let class = (i.code as u32) & 0x07;
            match class {
                c if c == libc::BPF_LD => {
                    acc = if i.k == 4 { arch } else { nr };
                    pc += 1;
                }
                c if c == libc::BPF_JMP => {
                    pc += 1 + if acc == i.k {
                        i.jt as usize
                    } else {
                        i.jf as usize
                    };
                }
                c if c == libc::BPF_RET => return i.k,
                _ => panic!("unexpected op"),
            }
        }
    }

    #[test]
    fn filter_semantics() {
        let denied: Vec<i64> = denied_syscalls().iter().map(|(_, n)| *n).collect();
        let f = build_filter(&denied);
        assert!(f.len() < 4096);
        for nr in &denied {
            assert_eq!(
                run(&f, AUDIT_ARCH, *nr as u32),
                SECCOMP_RET_ERRNO | libc::EPERM as u32
            );
        }
        for nr in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_clone,
            libc::SYS_execve,
        ] {
            assert_eq!(run(&f, AUDIT_ARCH, nr as u32), SECCOMP_RET_ALLOW);
        }
        assert_eq!(
            run(&f, 0x1234, libc::SYS_read as u32),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn empty_filter_allows() {
        let f = build_filter(&[]);
        assert_eq!(run(&f, AUDIT_ARCH, 0), SECCOMP_RET_ALLOW);
    }
}

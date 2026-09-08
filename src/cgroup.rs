//! cgroup v1 and v2 support for memory, cpu and pids limits.
//!
//! The *plan* (which file gets which value) is computed by pure functions so
//! it can be unit tested without root; `Cgroup` applies it.

use crate::state::{FinalStats, Limits};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const CFS_PERIOD_US: u64 = 100_000;
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
}

impl Version {
    pub fn as_str(self) -> &'static str {
        match self {
            Version::V1 => "v1",
            Version::V2 => "v2",
        }
    }
}

/// Detect the cgroup layout: a cgroup2 filesystem mounted at /sys/fs/cgroup
/// means unified (v2); anything else (tmpfs with per-controller mounts) is v1.
pub fn detect(base: &Path) -> Version {
    let c = std::ffi::CString::new(base.as_os_str().as_encoded_bytes()).unwrap();
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::statfs(c.as_ptr(), &mut st) };
    if r == 0 && st.f_type as i64 == CGROUP2_SUPER_MAGIC {
        Version::V2
    } else {
        Version::V1
    }
}

/// From /proc/self/mountinfo, find the v1 mount point for each controller.
pub fn parse_v1_mounts(mountinfo: &str) -> Vec<(String, PathBuf)> {
    let mut out = vec![];
    for line in mountinfo.lines() {
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };
        let mut post_it = post.split_whitespace();
        if post_it.next() != Some("cgroup") {
            continue;
        }
        let _src = post_it.next();
        let opts = post_it.next().unwrap_or("");
        let Some(mp) = pre.split_whitespace().nth(4) else {
            continue;
        };
        for o in opts.split(',') {
            if matches!(o, "memory" | "cpu" | "pids" | "cpuacct") {
                out.push((o.to_string(), PathBuf::from(mp)));
            }
        }
    }
    out
}

/// One write: (controller, file, value). Controller is "" for v2.
pub type Write = (&'static str, &'static str, String);

/// The ordered list of cgroup file writes enforcing `limits`.
pub fn plan(version: Version, l: &Limits, has_memsw: bool) -> Vec<Write> {
    let mut w = vec![];
    match version {
        Version::V1 => {
            if let Some(m) = l.memory {
                w.push(("memory", "memory.limit_in_bytes", m.to_string()));
                if has_memsw {
                    // memsw must be >= limit_in_bytes, so it goes second.
                    w.push(("memory", "memory.memsw.limit_in_bytes", m.to_string()));
                }
                w.push(("memory", "memory.swappiness", "0".into()));
            }
            if let Some(c) = l.cpus_milli {
                w.push(("cpu", "cpu.cfs_period_us", CFS_PERIOD_US.to_string()));
                w.push((
                    "cpu",
                    "cpu.cfs_quota_us",
                    (c * CFS_PERIOD_US / 1000).to_string(),
                ));
            }
            if let Some(p) = l.pids {
                w.push(("pids", "pids.max", p.to_string()));
            }
        }
        Version::V2 => {
            if let Some(m) = l.memory {
                w.push(("", "memory.max", m.to_string()));
                w.push(("", "memory.swap.max", "0".into()));
            }
            if let Some(c) = l.cpus_milli {
                w.push((
                    "",
                    "cpu.max",
                    format!("{} {}", c * CFS_PERIOD_US / 1000, CFS_PERIOD_US),
                ));
            }
            if let Some(p) = l.pids {
                w.push(("", "pids.max", p.to_string()));
            }
        }
    }
    w
}

/// Parse "key value" lines (cpu.stat, memory.events, memory.oom_control).
pub fn kv(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next() == Some(key)).then(|| it.next()?.parse().ok())?
    })
}

#[derive(Debug, Clone)]
pub struct Cgroup {
    pub version: Version,
    /// For v1: one directory per controller; for v2: a single directory.
    pub dirs: Vec<(String, PathBuf)>,
}

fn write_file(p: &Path, v: &str) -> io::Result<()> {
    fs::write(p, v)
        .map_err(|e| io::Error::new(e.kind(), format!("write {} = {v}: {e}", p.display())))
}

impl Cgroup {
    /// Create the cgroup for container `id` and apply limits.
    pub fn create(id: &str, limits: &Limits) -> io::Result<Cgroup> {
        let base = Path::new("/sys/fs/cgroup");
        let version = detect(base);
        let cg = match version {
            Version::V2 => {
                let parent = base.join("hull");
                fs::create_dir_all(&parent)?;
                // enable controllers for children (ignore ones not available)
                for c in ["+memory", "+cpu", "+pids"] {
                    let _ = fs::write(base.join("cgroup.subtree_control"), c);
                    let _ = fs::write(parent.join("cgroup.subtree_control"), c);
                }
                let d = parent.join(id);
                fs::create_dir_all(&d)?;
                Cgroup {
                    version,
                    dirs: vec![("".into(), d)],
                }
            }
            Version::V1 => {
                let mi = fs::read_to_string("/proc/self/mountinfo")?;
                let mut dirs = vec![];
                for (ctrl, mp) in parse_v1_mounts(&mi) {
                    if ctrl == "cpuacct" || dirs.iter().any(|(c, _)| c == &ctrl) {
                        continue;
                    }
                    let d = mp.join("hull").join(id);
                    fs::create_dir_all(&d)?;
                    dirs.push((ctrl, d));
                }
                Cgroup { version, dirs }
            }
        };
        let has_memsw = cg
            .dir("memory")
            .is_some_and(|d| d.join("memory.memsw.limit_in_bytes").exists());
        for (ctrl, file, val) in plan(version, limits, has_memsw) {
            let d = cg.dir(ctrl).ok_or_else(|| {
                io::Error::other(format!("cgroup controller '{ctrl}' not available"))
            });
            let d = match d {
                Ok(d) => d,
                Err(e) => {
                    cg.destroy();
                    return Err(e);
                }
            };
            if file == "memory.swappiness" || file == "memory.swap.max" {
                let _ = fs::write(d.join(file), &val); // best effort
                continue;
            }
            if let Err(e) = write_file(&d.join(file), &val) {
                cg.destroy();
                return Err(e);
            }
        }
        Ok(cg)
    }

    pub fn dir(&self, ctrl: &str) -> Option<&Path> {
        match self.version {
            Version::V2 => self.dirs.first().map(|(_, d)| d.as_path()),
            Version::V1 => self
                .dirs
                .iter()
                .find(|(c, _)| c == ctrl)
                .map(|(_, d)| d.as_path()),
        }
    }

    pub fn from_paths(version: &str, paths: &[String]) -> Cgroup {
        let version = if version == "v2" {
            Version::V2
        } else {
            Version::V1
        };
        let dirs = paths
            .iter()
            .map(|p| {
                let pb = PathBuf::from(p);
                let ctrl = if version == Version::V2 {
                    String::new()
                } else {
                    pb.parent()
                        .and_then(|p| p.parent())
                        .and_then(|p| p.file_name())
                        .map(|n| {
                            let n = n.to_string_lossy();
                            n.split(',')
                                .find(|c| matches!(*c, "memory" | "cpu" | "pids"))
                                .unwrap_or(&n)
                                .to_string()
                        })
                        .unwrap_or_default()
                };
                (ctrl, pb)
            })
            .collect();
        Cgroup { version, dirs }
    }

    pub fn paths(&self) -> Vec<String> {
        self.dirs
            .iter()
            .map(|(_, d)| d.display().to_string())
            .collect()
    }

    /// Move a process into every hierarchy of this cgroup.
    pub fn add(&self, pid: i32) -> io::Result<()> {
        for (_, d) in &self.dirs {
            write_file(&d.join("cgroup.procs"), &pid.to_string())?;
        }
        Ok(())
    }

    pub fn stats(&self) -> FinalStats {
        let read = |c: &str, f: &str| self.dir(c).and_then(|d| fs::read_to_string(d.join(f)).ok());
        let num = |c: &str, f: &str| read(c, f).and_then(|s| s.trim().parse().ok());
        match self.version {
            Version::V1 => FinalStats {
                oom_kills: read("memory", "memory.oom_control").and_then(|s| kv(&s, "oom_kill")),
                memory_failcnt: num("memory", "memory.failcnt"),
                cpu_nr_throttled: read("cpu", "cpu.stat").and_then(|s| kv(&s, "nr_throttled")),
                cpu_usage_usec: read("cpu", "cpu.stat")
                    .and_then(|s| kv(&s, "usage_usec"))
                    .or_else(|| {
                        // cpuacct is usually co-mounted with cpu on v1
                        num("cpu", "cpuacct.usage").map(|ns: u64| ns / 1000)
                    }),
                pids_peak: num("pids", "pids.peak"),
            },
            Version::V2 => FinalStats {
                oom_kills: read("", "memory.events").and_then(|s| kv(&s, "oom_kill")),
                memory_failcnt: read("", "memory.events").and_then(|s| kv(&s, "max")),
                cpu_nr_throttled: read("", "cpu.stat").and_then(|s| kv(&s, "nr_throttled")),
                cpu_usage_usec: read("", "cpu.stat").and_then(|s| kv(&s, "usage_usec")),
                pids_peak: num("", "pids.peak"),
            },
        }
    }

    fn procs(&self) -> Vec<i32> {
        let mut v = vec![];
        for (_, d) in &self.dirs {
            if let Ok(s) = fs::read_to_string(d.join("cgroup.procs")) {
                v.extend(s.lines().filter_map(|l| l.trim().parse::<i32>().ok()));
            }
        }
        v.sort();
        v.dedup();
        v
    }

    /// Kill leftovers and remove the cgroup directories (retrying while the
    /// kernel finishes tearing tasks down).
    pub fn destroy(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        for (_, d) in &self.dirs {
            loop {
                for p in self.procs() {
                    unsafe { libc::kill(p, libc::SIGKILL) };
                }
                match fs::remove_dir(d) {
                    Ok(()) => break,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                    Err(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    Err(e) => {
                        eprintln!(
                            "hull: warning: could not remove cgroup {}: {e}",
                            d.display()
                        );
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MI: &str = "\
25 30 0:22 / /sys/fs/cgroup rw,relatime - tmpfs tmpfs rw,mode=755
26 25 0:23 / /sys/fs/cgroup/cpu rw,relatime - cgroup cgroup rw,cpu
27 25 0:24 / /sys/fs/cgroup/memory rw,relatime - cgroup cgroup rw,memory
28 25 0:25 / /sys/fs/cgroup/pids rw,relatime - cgroup cgroup rw,pids
29 25 0:26 / /sys/fs/cgroup/cpu,cpuacct rw,relatime - cgroup cgroup rw,cpu,cpuacct
30 25 0:27 / /sys/fs/cgroup/unified rw,relatime - cgroup2 cgroup2 rw
31 30 8:1 / / rw - ext4 /dev/vda rw";

    #[test]
    fn mountinfo_parsing() {
        let m = parse_v1_mounts(MI);
        assert!(m.contains(&("cpu".into(), "/sys/fs/cgroup/cpu".into())));
        assert!(m.contains(&("memory".into(), "/sys/fs/cgroup/memory".into())));
        assert!(m.contains(&("pids".into(), "/sys/fs/cgroup/pids".into())));
        assert!(m.contains(&("cpuacct".into(), "/sys/fs/cgroup/cpu,cpuacct".into())));
        assert!(
            !m.iter().any(|(_, p)| p.ends_with("unified")),
            "cgroup2 is not v1"
        );
    }

    #[test]
    fn v1_plan() {
        let l = Limits {
            memory: Some(64 << 20),
            cpus_milli: Some(500),
            pids: Some(64),
        };
        let p = plan(Version::V1, &l, true);
        assert_eq!(
            p[0],
            ("memory", "memory.limit_in_bytes", (64u64 << 20).to_string())
        );
        assert_eq!(p[1].1, "memory.memsw.limit_in_bytes");
        assert!(p.contains(&("cpu", "cpu.cfs_quota_us", "50000".into())));
        assert!(p.contains(&("cpu", "cpu.cfs_period_us", "100000".into())));
        assert!(p.contains(&("pids", "pids.max", "64".into())));
        assert!(!plan(Version::V1, &l, false)
            .iter()
            .any(|w| w.1.contains("memsw")));
    }

    #[test]
    fn v2_plan() {
        let l = Limits {
            memory: Some(1 << 30),
            cpus_milli: Some(1500),
            pids: Some(10),
        };
        let p = plan(Version::V2, &l, false);
        assert!(p.contains(&("", "memory.max", (1u64 << 30).to_string())));
        assert!(p.contains(&("", "cpu.max", "150000 100000".into())));
        assert!(p.contains(&("", "pids.max", "10".into())));
        assert!(plan(Version::V2, &Limits::default(), false).is_empty());
    }

    #[test]
    fn kv_parsing() {
        let s = "nr_periods 10\nnr_throttled 4\nthrottled_time 99\n";
        assert_eq!(kv(s, "nr_throttled"), Some(4));
        assert_eq!(kv(s, "nr_periods"), Some(10));
        assert_eq!(kv(s, "missing"), None);
        assert_eq!(
            kv("oom_kill_disable 0\nunder_oom 0\noom_kill 2\n", "oom_kill"),
            Some(2)
        );
    }

    #[test]
    fn from_paths_recovers_controllers() {
        let c = Cgroup::from_paths(
            "v1",
            &[
                "/sys/fs/cgroup/memory/hull/abc".into(),
                "/sys/fs/cgroup/pids/hull/abc".into(),
            ],
        );
        assert_eq!(
            c.dir("memory").unwrap(),
            Path::new("/sys/fs/cgroup/memory/hull/abc")
        );
        assert!(c.dir("cpu").is_none());
        let c2 = Cgroup::from_paths("v2", &["/sys/fs/cgroup/hull/abc".into()]);
        assert_eq!(
            c2.dir("memory").unwrap(),
            Path::new("/sys/fs/cgroup/hull/abc")
        );
    }

    #[test]
    fn detect_runs() {
        // Just make sure detection does not crash on this host.
        let v = detect(Path::new("/sys/fs/cgroup"));
        assert!(matches!(v, Version::V1 | Version::V2));
    }
}

//! Container state persisted as JSON under `<root>/containers/<id>/state.json`.

use crate::cli::{NetMode, Volume};
use crate::util::{atomic_write, pid_alive};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Created,
    Running,
    Exited,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    pub memory: Option<u64>,
    pub cpus_milli: Option<u64>,
    pub pids: Option<u64>,
}

/// Resource statistics captured from the cgroup right before it is removed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FinalStats {
    pub oom_kills: Option<u64>,
    pub memory_failcnt: Option<u64>,
    pub cpu_nr_throttled: Option<u64>,
    pub cpu_usage_usec: Option<u64>,
    pub pids_peak: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetInfo {
    pub mode: NetMode,
    pub ip: Option<String>,
    pub host_veth: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainerState {
    pub id: String,
    pub name: Option<String>,
    pub image: String,
    pub image_digest: String,
    pub cmd: Vec<String>,
    pub hostname: String,
    pub status: Status,
    /// Host pid of the container's init (PID 1 inside).
    pub pid: Option<i32>,
    pub pid_start_time: Option<u64>,
    /// Host pid of the hull process supervising the container.
    pub supervisor_pid: Option<i32>,
    pub exit_code: Option<i32>,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub limits: Limits,
    /// "pivot_root" or "chroot".
    pub rootfs_mode: Option<String>,
    pub cgroup_version: Option<String>,
    pub cgroup_paths: Vec<String>,
    pub volumes: Vec<Volume>,
    pub net: NetInfo,
    pub stats: FinalStats,
    pub error: Option<String>,
}

pub fn containers_dir(root: &Path) -> PathBuf {
    root.join("containers")
}

pub fn container_dir(root: &Path, id: &str) -> PathBuf {
    containers_dir(root).join(id)
}

impl ContainerState {
    pub fn dir(&self, root: &Path) -> PathBuf {
        container_dir(root, &self.id)
    }

    pub fn save(&self, root: &Path) -> io::Result<()> {
        let data = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        atomic_write(&self.dir(root).join("state.json"), &data)
    }

    pub fn load(root: &Path, id: &str) -> io::Result<Self> {
        let data = fs::read(container_dir(root, id).join("state.json"))?;
        serde_json::from_slice(&data).map_err(io::Error::other)
    }

    /// Is the container's init process still alive?
    pub fn is_alive(&self) -> bool {
        self.status == Status::Running
            && self.pid.is_some_and(|p| pid_alive(p, self.pid_start_time))
    }

    /// Status for display: a "running" container whose init vanished without
    /// its supervisor recording an exit is reported as "dead".
    pub fn display_status(&self) -> String {
        match self.status {
            Status::Running if !self.is_alive() => "dead".into(),
            Status::Running => "running".into(),
            Status::Created => "created".into(),
            Status::Exited => format!("exited ({})", self.exit_code.unwrap_or(-1)),
        }
    }
}

/// Load every container state (skipping unreadable entries), sorted by creation.
pub fn list(root: &Path) -> Vec<ContainerState> {
    let mut v = vec![];
    if let Ok(rd) = fs::read_dir(containers_dir(root)) {
        for e in rd.flatten() {
            if let Some(id) = e.file_name().to_str() {
                if let Ok(s) = ContainerState::load(root, id) {
                    v.push(s);
                }
            }
        }
    }
    v.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
    v
}

/// Resolve a user supplied reference: full id, unique id prefix, or name.
pub fn resolve(root: &Path, r: &str) -> Result<ContainerState, String> {
    let all = list(root);
    if let Some(s) = all
        .iter()
        .find(|s| s.id == r || s.name.as_deref() == Some(r))
    {
        return Ok(s.clone());
    }
    let matches: Vec<&ContainerState> = all.iter().filter(|s| s.id.starts_with(r)).collect();
    match matches.as_slice() {
        [one] if !r.is_empty() => Ok((*one).clone()),
        [] | [_] => Err(format!("no such container: {r}")),
        _ => Err(format!("ambiguous container reference: {r}")),
    }
}

#[cfg(test)]
pub fn sample(id: &str) -> ContainerState {
    ContainerState {
        id: id.into(),
        name: None,
        image: "alpine".into(),
        image_digest: "sha256:00".into(),
        cmd: vec!["sh".into()],
        hostname: id.into(),
        status: Status::Created,
        pid: None,
        pid_start_time: None,
        supervisor_pid: None,
        exit_code: None,
        created_at: 1,
        started_at: None,
        finished_at: None,
        limits: Limits::default(),
        rootfs_mode: None,
        cgroup_version: None,
        cgroup_paths: vec![],
        volumes: vec![],
        net: NetInfo {
            mode: NetMode::None,
            ip: None,
            host_veth: None,
        },
        stats: FinalStats::default(),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::random_id;

    fn tmproot() -> PathBuf {
        std::env::temp_dir().join(format!("hull-state-ut-{}", random_id()))
    }

    #[test]
    fn roundtrip_and_list() {
        let root = tmproot();
        let mut a = sample("aaaa11112222");
        a.created_at = 5;
        a.limits.memory = Some(1 << 20);
        a.name = Some("web".into());
        a.save(&root).unwrap();
        let mut b = sample("aaab33334444");
        b.created_at = 3;
        b.status = Status::Exited;
        b.exit_code = Some(7);
        b.save(&root).unwrap();
        assert_eq!(ContainerState::load(&root, &a.id).unwrap(), a);
        let l = list(&root);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].id, b.id, "sorted by creation time");
        assert_eq!(b.display_status(), "exited (7)");
        // resolution
        assert_eq!(resolve(&root, "web").unwrap().id, a.id);
        assert_eq!(resolve(&root, "aaab").unwrap().id, b.id);
        assert!(resolve(&root, "aaa").unwrap_err().contains("ambiguous"));
        assert!(resolve(&root, "zzz").unwrap_err().contains("no such"));
        assert!(resolve(&root, "").is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn json_shape_is_stable() {
        let s = sample("abc");
        let j: serde_json::Value = serde_json::to_value(&s).unwrap();
        assert_eq!(j["status"], "created");
        assert_eq!(j["net"]["mode"], "none");
        assert!(j["limits"]["memory"].is_null());
    }

    #[test]
    fn dead_detection() {
        let mut s = sample("abc");
        s.status = Status::Running;
        s.pid = Some(std::process::id() as i32);
        s.pid_start_time = crate::util::proc_start_time(s.pid.unwrap());
        assert!(s.is_alive());
        assert_eq!(s.display_status(), "running");
        s.pid_start_time = Some(1); // pid reused by another process
        assert!(!s.is_alive());
        assert_eq!(s.display_status(), "dead");
    }

    #[test]
    fn list_ignores_garbage() {
        let root = tmproot();
        fs::create_dir_all(containers_dir(&root).join("junk")).unwrap();
        fs::write(containers_dir(&root).join("junk/state.json"), "{not json").unwrap();
        assert!(list(&root).is_empty());
        fs::remove_dir_all(&root).unwrap();
    }
}

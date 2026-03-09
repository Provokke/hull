//! Optional bridge networking: `hull0` bridge (10.88.0.1/16), one veth pair
//! per container, MASQUERADE for outbound traffic. Uses the `ip` and
//! `iptables` tools; the container side is configured by running `ip` inside
//! the container's network namespace via setns.

use crate::state::{self, ContainerState, Status};
use std::collections::HashSet;
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

pub const BRIDGE: &str = "hull0";
pub const GATEWAY: &str = "10.88.0.1";
pub const SUBNET: &str = "10.88.0.0/16";

fn sh(args: &[&str]) -> Result<(), String> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|e| format!("{}: {e}", args[0]))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "`{}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn in_netns(pid: i32, args: &[&str]) -> Result<(), String> {
    let ns = std::fs::File::open(format!("/proc/{pid}/ns/net")).map_err(|e| e.to_string())?;
    let mut c = Command::new(args[0]);
    c.args(&args[1..]);
    unsafe {
        c.pre_exec(move || {
            nix::sched::setns(ns.as_fd(), nix::sched::CloneFlags::CLONE_NEWNET)
                .map_err(std::io::Error::from)
        });
    }
    let out = c.output().map_err(|e| format!("{}: {e}", args[0]))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "`{}` (in container netns) failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Pick the lowest free address in 10.88.0.0/16 (skipping .0.0, .0.1 and
/// broadcast).
pub fn allocate_ip(used: &HashSet<String>) -> Option<String> {
    for n in 2u32..65535 {
        let ip = format!("10.88.{}.{}", n >> 8, n & 0xff);
        if n & 0xff == 0 || n & 0xff == 255 {
            continue;
        }
        if !used.contains(&ip) {
            return Some(ip);
        }
    }
    None
}

pub fn veth_names(id: &str) -> (String, String) {
    let short = &id[..id.len().min(10)];
    (format!("hv{short}"), format!("hc{short}"))
}

fn ensure_bridge() -> Result<(), String> {
    if !Path::new("/sys/class/net").join(BRIDGE).exists() {
        sh(&["ip", "link", "add", BRIDGE, "type", "bridge"])?;
        sh(&["ip", "addr", "add", &format!("{GATEWAY}/16"), "dev", BRIDGE])?;
    }
    sh(&["ip", "link", "set", BRIDGE, "up"])?;
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");
    let rules: [&[&str]; 3] = [
        &[
            "-t",
            "nat",
            "POSTROUTING",
            "-s",
            SUBNET,
            "!",
            "-o",
            BRIDGE,
            "-j",
            "MASQUERADE",
        ],
        &["-t", "filter", "FORWARD", "-i", BRIDGE, "-j", "ACCEPT"],
        &["-t", "filter", "FORWARD", "-o", BRIDGE, "-j", "ACCEPT"],
    ];
    for r in rules {
        let (table, rest) = (&r[..2], &r[2..]);
        let mut check = vec!["iptables"];
        check.extend_from_slice(table);
        check.push("-C");
        check.extend_from_slice(rest);
        if sh(&check).is_err() {
            let mut add = vec!["iptables"];
            add.extend_from_slice(table);
            add.push("-A");
            add.extend_from_slice(rest);
            sh(&add)?;
        }
    }
    Ok(())
}

/// Create the veth pair for container `id` whose init has host pid `pid`.
/// Returns (container ip, host veth name).
pub fn setup(root: &Path, id: &str, pid: i32) -> Result<(String, String), String> {
    ensure_bridge()?;
    let used: HashSet<String> = state::list(root)
        .into_iter()
        .filter(|s| s.status == Status::Running && s.id != id)
        .filter_map(|s| s.net.ip)
        .collect();
    let ip = allocate_ip(&used).ok_or("no free addresses")?;
    let (host, peer) = veth_names(id);
    sh(&[
        "ip", "link", "add", &host, "type", "veth", "peer", "name", &peer,
    ])?;
    let res = (|| {
        sh(&["ip", "link", "set", &host, "master", BRIDGE, "up"])?;
        sh(&["ip", "link", "set", &peer, "netns", &pid.to_string()])?;
        in_netns(pid, &["ip", "link", "set", &peer, "name", "eth0"])?;
        in_netns(
            pid,
            &["ip", "addr", "add", &format!("{ip}/16"), "dev", "eth0"],
        )?;
        in_netns(pid, &["ip", "link", "set", "eth0", "up"])?;
        in_netns(pid, &["ip", "route", "add", "default", "via", GATEWAY])
    })();
    if let Err(e) = res {
        let _ = sh(&["ip", "link", "del", &host]);
        return Err(e);
    }
    Ok((ip, host))
}

pub fn teardown(st: &ContainerState) {
    if let Some(v) = &st.net.host_veth {
        if Path::new("/sys/class/net").join(v).exists() {
            let _ = sh(&["ip", "link", "del", v]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_allocation() {
        let mut used = HashSet::new();
        assert_eq!(allocate_ip(&used).unwrap(), "10.88.0.2");
        used.insert("10.88.0.2".to_string());
        assert_eq!(allocate_ip(&used).unwrap(), "10.88.0.3");
        for i in 2..255 {
            used.insert(format!("10.88.0.{i}"));
        }
        assert_eq!(allocate_ip(&used).unwrap(), "10.88.1.1");
    }

    #[test]
    fn veth_names_fit_ifnamsiz() {
        let (h, p) = veth_names("0123456789ab");
        assert!(h.len() <= 15 && p.len() <= 15);
        assert_ne!(h, p);
    }
}

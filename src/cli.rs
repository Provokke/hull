//! Hand-written command line parsing (kept dependency free and unit tested).

use crate::util::{parse_cpus, parse_size};

/// Network mode for a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetMode {
    /// Fresh network namespace with only loopback.
    None,
    /// veth pair attached to the `hull0` bridge with NAT to the outside.
    Bridge,
}

/// A `-v host:container[:ro]` bind mount.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Volume {
    pub host: String,
    pub container: String,
    pub readonly: bool,
}

/// Everything `hull run` needs.
#[derive(Debug, Clone, PartialEq)]
pub struct RunOpts {
    pub image: String,
    pub cmd: Vec<String>,
    pub memory: Option<u64>,
    pub cpus_milli: Option<u64>,
    pub pids: Option<u64>,
    pub hostname: Option<String>,
    pub net: NetMode,
    pub volumes: Vec<Volume>,
    pub detach: bool,
    pub name: Option<String>,
    pub env: Vec<(String, String)>,
    pub seccomp: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Run(RunOpts),
    Exec { id: String, cmd: Vec<String> },
    Ps { all: bool },
    Stop { id: String, timeout: u64 },
    Rm { ids: Vec<String>, force: bool },
    Logs { id: String },
    Images,
    Pull { name: String, busybox_only: bool },
    Import { path: String, name: Option<String> },
    Inspect { id: String },
    Help,
}

pub const USAGE: &str = "\
hull - a small Linux container runtime

USAGE:
  hull run [-d] [--name N] [--memory 64m] [--cpus 0.5] [--pids 64] [--hostname H]
           [--net none|bridge] [-v host:ctr[:ro]]... [-e K=V]... [--no-seccomp]
           <image> <cmd...>
  hull exec <id> <cmd...>        run a command inside a running container
  hull ps [-a]                   list running (or all) containers
  hull stop [-t secs] <id>       SIGTERM (forwarded by init), then SIGKILL
  hull rm [-f] <id>...           remove container(s)
  hull logs <id>                 print captured stdout/stderr
  hull inspect <id>              print the container state JSON
  hull images                    list images
  hull pull <alpine|busybox> [--busybox]
  hull import <tar[.gz]> [name]  import a rootfs tarball
State lives under $HULL_ROOT (default /var/lib/hull).";

fn need<'a>(it: &mut std::slice::Iter<'a, String>, flag: &str) -> Result<&'a String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}

pub fn parse_volume(s: &str) -> Result<Volume, String> {
    let parts: Vec<&str> = s.split(':').collect();
    let (host, ctr, ro) = match parts.as_slice() {
        [h, c] => (*h, *c, false),
        [h, c, "ro"] => (*h, *c, true),
        [h, c, "rw"] => (*h, *c, false),
        _ => return Err(format!("invalid volume '{s}' (want host:container[:ro])")),
    };
    if !host.starts_with('/') || !ctr.starts_with('/') {
        return Err(format!("volume paths must be absolute: '{s}'"));
    }
    if ctr.split('/').any(|c| c == "..") || host.split('/').any(|c| c == "..") {
        return Err(format!("volume paths must not contain '..': '{s}'"));
    }
    if ctr == "/" {
        return Err("cannot mount a volume over the container root".into());
    }
    Ok(Volume {
        host: host.to_string(),
        container: ctr.to_string(),
        readonly: ro,
    })
}

pub fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 64
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !h.starts_with('-')
}

fn parse_run(args: &[String]) -> Result<RunOpts, String> {
    let mut o = RunOpts {
        image: String::new(),
        cmd: vec![],
        memory: None,
        cpus_milli: None,
        pids: None,
        hostname: None,
        net: NetMode::None,
        volumes: vec![],
        detach: false,
        name: None,
        env: vec![],
        seccomp: true,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        // support --flag=value
        let (flag, inline): (&str, Option<String>) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (a.as_str(), None),
        };
        let val = |it: &mut std::slice::Iter<String>| -> Result<String, String> {
            match &inline {
                Some(v) => Ok(v.clone()),
                None => need(it, flag).cloned(),
            }
        };
        match flag {
            "-d" | "--detach" => o.detach = true,
            "--memory" | "-m" => o.memory = Some(parse_size(&val(&mut it)?)?),
            "--cpus" => o.cpus_milli = Some(parse_cpus(&val(&mut it)?)?),
            "--pids" | "--pids-limit" => {
                let v = val(&mut it)?;
                let n: u64 = v.parse().map_err(|_| format!("invalid pids limit '{v}'"))?;
                if n == 0 {
                    return Err("pids limit must be > 0".into());
                }
                o.pids = Some(n);
            }
            "--hostname" | "-h" => {
                let h = val(&mut it)?;
                if !valid_hostname(&h) {
                    return Err(format!("invalid hostname '{h}'"));
                }
                o.hostname = Some(h);
            }
            "--name" => {
                let n = val(&mut it)?;
                if !valid_hostname(&n) {
                    return Err(format!("invalid name '{n}'"));
                }
                o.name = Some(n);
            }
            "--net" | "--network" => {
                o.net = match val(&mut it)?.as_str() {
                    "none" => NetMode::None,
                    "bridge" => NetMode::Bridge,
                    other => return Err(format!("unknown network mode '{other}'")),
                }
            }
            "-v" | "--volume" => o.volumes.push(parse_volume(&val(&mut it)?)?),
            "-e" | "--env" => {
                let kv = val(&mut it)?;
                let (k, v) = kv
                    .split_once('=')
                    .ok_or_else(|| format!("invalid env '{kv}' (want K=V)"))?;
                if k.is_empty() {
                    return Err(format!("invalid env '{kv}'"));
                }
                o.env.push((k.to_string(), v.to_string()));
            }
            "--no-seccomp" => o.seccomp = false,
            s if s.starts_with('-') && o.image.is_empty() => {
                return Err(format!("unknown run option '{s}'"))
            }
            _ => {
                o.image = a.clone();
                o.cmd = it.cloned().collect();
                break;
            }
        }
    }
    if o.image.is_empty() {
        return Err("run: missing image".into());
    }
    if o.cmd.is_empty() {
        o.cmd = vec!["/bin/sh".into()];
    }
    Ok(o)
}

pub fn parse(args: &[String]) -> Result<Command, String> {
    let Some((sub, rest)) = args.split_first() else {
        return Ok(Command::Help);
    };
    match sub.as_str() {
        "run" => Ok(Command::Run(parse_run(rest)?)),
        "exec" => {
            let (id, cmd) = rest.split_first().ok_or("exec: missing container id")?;
            if cmd.is_empty() {
                return Err("exec: missing command".into());
            }
            Ok(Command::Exec {
                id: id.clone(),
                cmd: cmd.to_vec(),
            })
        }
        "ps" => match rest {
            [] => Ok(Command::Ps { all: false }),
            [a] if a == "-a" || a == "--all" => Ok(Command::Ps { all: true }),
            _ => Err("usage: hull ps [-a]".into()),
        },
        "stop" => {
            let mut timeout = 10;
            let mut id = None;
            let mut it = rest.iter();
            while let Some(a) = it.next() {
                if a == "-t" || a == "--time" {
                    let v = need(&mut it, a)?;
                    timeout = v.parse().map_err(|_| format!("invalid timeout '{v}'"))?;
                } else if id.is_none() {
                    id = Some(a.clone());
                } else {
                    return Err("usage: hull stop [-t secs] <id>".into());
                }
            }
            Ok(Command::Stop {
                id: id.ok_or("stop: missing container id")?,
                timeout,
            })
        }
        "rm" => {
            let force = rest.iter().any(|a| a == "-f" || a == "--force");
            let ids: Vec<String> = rest
                .iter()
                .filter(|a| !a.starts_with('-'))
                .cloned()
                .collect();
            if ids.is_empty() {
                return Err("rm: missing container id".into());
            }
            Ok(Command::Rm { ids, force })
        }
        "logs" => match rest {
            [id] => Ok(Command::Logs { id: id.clone() }),
            _ => Err("usage: hull logs <id>".into()),
        },
        "inspect" => match rest {
            [id] => Ok(Command::Inspect { id: id.clone() }),
            _ => Err("usage: hull inspect <id>".into()),
        },
        "images" => Ok(Command::Images),
        "pull" => {
            let busybox_only = rest.iter().any(|a| a == "--busybox");
            let names: Vec<&String> = rest.iter().filter(|a| !a.starts_with('-')).collect();
            match names.as_slice() {
                [n] => Ok(Command::Pull {
                    name: (*n).clone(),
                    busybox_only,
                }),
                _ => Err("usage: hull pull <alpine|busybox> [--busybox]".into()),
            }
        }
        "import" => match rest {
            [p] => Ok(Command::Import {
                path: p.clone(),
                name: None,
            }),
            [p, n] => Ok(Command::Import {
                path: p.clone(),
                name: Some(n.clone()),
            }),
            _ => Err("usage: hull import <tar> [name]".into()),
        },
        "help" | "-h" | "--help" => Ok(Command::Help),
        other => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn run_full() {
        let c = parse(&v(
            "run -d --memory 64m --cpus 0.5 --pids 64 --hostname box --net bridge -v /a:/b -v /c:/d:ro -e X=1 --name web alpine sh -c 'echo hi'",
        ))
        .unwrap();
        let Command::Run(o) = c else { panic!() };
        assert!(o.detach);
        assert_eq!(o.memory, Some(64 << 20));
        assert_eq!(o.cpus_milli, Some(500));
        assert_eq!(o.pids, Some(64));
        assert_eq!(o.hostname.as_deref(), Some("box"));
        assert_eq!(o.net, NetMode::Bridge);
        assert_eq!(o.volumes.len(), 2);
        assert!(o.volumes[1].readonly);
        assert_eq!(o.env, vec![("X".into(), "1".into())]);
        assert_eq!(o.name.as_deref(), Some("web"));
        assert_eq!(o.image, "alpine");
        assert_eq!(o.cmd[0], "sh");
        assert!(o.seccomp);
    }

    #[test]
    fn run_equals_syntax_and_cmd_flags_untouched() {
        let Command::Run(o) = parse(&v("run --memory=32m img ls -la --memory")).unwrap() else {
            panic!()
        };
        assert_eq!(o.memory, Some(32 << 20));
        assert_eq!(o.cmd, v("ls -la --memory"));
    }

    #[test]
    fn run_defaults_to_shell() {
        let Command::Run(o) = parse(&v("run img")).unwrap() else {
            panic!()
        };
        assert_eq!(o.cmd, vec!["/bin/sh".to_string()]);
        assert_eq!(o.net, NetMode::None);
    }

    #[test]
    fn run_errors() {
        for bad in [
            "run",
            "run --memory",
            "run --memory lots img x",
            "run --cpus 0 img x",
            "run --pids 0 img x",
            "run --pids x img x",
            "run --net host img x",
            "run --hostname bad_name! img x",
            "run -v rel:/x img x",
            "run -v /a:/ img x",
            "run -v /a/../b:/x img x",
            "run -e =1 img x",
            "run --bogus img",
        ] {
            assert!(parse(&v(bad)).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn other_commands() {
        assert_eq!(parse(&v("ps")).unwrap(), Command::Ps { all: false });
        assert_eq!(parse(&v("ps -a")).unwrap(), Command::Ps { all: true });
        assert_eq!(
            parse(&v("stop -t 3 abc")).unwrap(),
            Command::Stop {
                id: "abc".into(),
                timeout: 3
            }
        );
        assert_eq!(
            parse(&v("rm -f a b")).unwrap(),
            Command::Rm {
                ids: v("a b"),
                force: true
            }
        );
        assert_eq!(
            parse(&v("exec abc ls /")).unwrap(),
            Command::Exec {
                id: "abc".into(),
                cmd: v("ls /")
            }
        );
        assert_eq!(parse(&v("images")).unwrap(), Command::Images);
        assert_eq!(
            parse(&v("pull alpine --busybox")).unwrap(),
            Command::Pull {
                name: "alpine".into(),
                busybox_only: true
            }
        );
        assert_eq!(
            parse(&v("import /x.tar foo")).unwrap(),
            Command::Import {
                path: "/x.tar".into(),
                name: Some("foo".into())
            }
        );
        assert_eq!(parse(&[]).unwrap(), Command::Help);
        assert!(parse(&v("exec abc")).is_err());
        assert!(parse(&v("frobnicate")).is_err());
        assert!(parse(&v("logs")).is_err());
    }

    proptest::proptest! {
        #[test]
        fn parse_never_panics(args in proptest::collection::vec("[-a-z0-9=:/.]{0,8}", 0..8)) {
            let mut full = vec!["run".to_string()];
            full.extend(args.clone());
            let _ = parse(&full);
            let _ = parse(&args);
        }
    }
}

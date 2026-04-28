//! Small helpers shared by the rest of the runtime: size parsing, ids,
//! atomic file writes and timestamps.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default root of all runtime state. Every file hull creates lives below
/// this directory (or below `$HULL_ROOT` when set).
pub const DEFAULT_ROOT: &str = "/var/lib/hull";

/// Returns the state root, honouring `$HULL_ROOT`.
pub fn state_root() -> PathBuf {
    match std::env::var_os("HULL_ROOT") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(DEFAULT_ROOT),
    }
}

/// Parse a human memory size such as `64m`, `1G`, `512k`, `1024` (bytes).
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".into());
    }
    let lower = s.to_ascii_lowercase();
    let trimmed = lower.strip_suffix('b').unwrap_or(&lower);
    let trimmed = trimmed.strip_suffix('i').unwrap_or(trimmed);
    let (num, mult): (&str, u64) = match trimmed.chars().last() {
        Some('k') => (&trimmed[..trimmed.len() - 1], 1 << 10),
        Some('m') => (&trimmed[..trimmed.len() - 1], 1 << 20),
        Some('g') => (&trimmed[..trimmed.len() - 1], 1 << 30),
        Some('t') => (&trimmed[..trimmed.len() - 1], 1 << 40),
        _ => (trimmed, 1),
    };
    if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("invalid size '{s}'"));
    }
    let n: u64 = num.parse().map_err(|_| format!("invalid size '{s}'"))?;
    let v = n
        .checked_mul(mult)
        .ok_or_else(|| format!("size '{s}' overflows"))?;
    if v == 0 {
        return Err("size must be > 0".into());
    }
    Ok(v)
}

/// Format a byte count the way `parse_size` accepts it (largest exact unit).
pub fn format_size(v: u64) -> String {
    for (suffix, mult) in [
        ("t", 1u64 << 40),
        ("g", 1 << 30),
        ("m", 1 << 20),
        ("k", 1 << 10),
    ] {
        if v >= mult && v.is_multiple_of(mult) {
            return format!("{}{}", v / mult, suffix);
        }
    }
    v.to_string()
}

/// Parse a fractional CPU count such as `0.5` or `2` into millicpus.
pub fn parse_cpus(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (int, frac) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    if (int.is_empty() && frac.is_empty())
        || !int.chars().all(|c| c.is_ascii_digit())
        || !frac.chars().all(|c| c.is_ascii_digit())
        || frac.len() > 3
    {
        return Err(format!(
            "invalid cpu count '{s}' (use e.g. 0.5, 2, max 3 decimals)"
        ));
    }
    let i: u64 = if int.is_empty() {
        0
    } else {
        int.parse()
            .map_err(|_| format!("invalid cpu count '{s}'"))?
    };
    let mut f: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse().unwrap()
    };
    for _ in frac.len()..3 {
        f *= 10;
    }
    let milli = i
        .checked_mul(1000)
        .and_then(|v| v.checked_add(f))
        .ok_or("cpu count too large")?;
    if milli == 0 {
        return Err("cpu count must be > 0".into());
    }
    Ok(milli)
}

/// A random 12 hex character id from the kernel RNG.
pub fn random_id() -> String {
    let mut buf = [0u8; 6];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("read /dev/urandom");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Seconds since the epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write a file atomically (write to a temp sibling, fsync, rename).
pub fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("f"),
        std::process::id()
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Human friendly relative time ("5s ago", "3m ago").
pub fn ago(then: u64, now: u64) -> String {
    let d = now.saturating_sub(then);
    match d {
        0..=59 => format!("{d}s ago"),
        60..=3599 => format!("{}m ago", d / 60),
        3600..=86399 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86400),
    }
}

/// Start time (in clock ticks since boot) of a process, field 22 of
/// `/proc/<pid>/stat`. Used to detect pid reuse.
pub fn proc_start_time(pid: i32) -> Option<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_stat_start_time(&s)
}

/// Parse field 22 out of a `/proc/<pid>/stat` line (the comm field may
/// contain spaces and parentheses, so split after the last ')').
pub fn parse_stat_start_time(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    // after ')' the fields start at #3 (state); start time is #22.
    rest.split_whitespace().nth(22 - 3)?.parse().ok()
}

/// Is the process `pid` alive and is it the same process (same start time)?
pub fn pid_alive(pid: i32, start_time: Option<u64>) -> bool {
    if pid <= 0 {
        return false;
    }
    match (proc_start_time(pid), start_time) {
        (Some(now), Some(expected)) => now == expected,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("64m").unwrap(), 64 << 20);
        assert_eq!(parse_size("64M").unwrap(), 64 << 20);
        assert_eq!(parse_size("64MiB").unwrap(), 64 << 20);
        assert_eq!(parse_size("64mb").unwrap(), 64 << 20);
        assert_eq!(parse_size("1g").unwrap(), 1 << 30);
        assert_eq!(parse_size("512k").unwrap(), 512 << 10);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        for bad in [
            "",
            "m",
            "-1m",
            "1.5m",
            "abc",
            "0",
            "99999999999999999999t",
            "12x",
        ] {
            assert!(parse_size(bad).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn cpus() {
        assert_eq!(parse_cpus("0.5").unwrap(), 500);
        assert_eq!(parse_cpus(".25").unwrap(), 250);
        assert_eq!(parse_cpus("2").unwrap(), 2000);
        assert_eq!(parse_cpus("1.125").unwrap(), 1125);
        for bad in ["", ".", "0", "0.0", "1.2345", "a", "-1", "1..2"] {
            assert!(parse_cpus(bad).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn ids_are_hex_and_distinct() {
        let a = random_id();
        let b = random_id();
        assert_eq!(a.len(), 12);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn stat_parsing_handles_weird_comm() {
        let line = "1234 (we ird) pr) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10";
        assert_eq!(parse_stat_start_time(line), Some(987654));
        assert_eq!(parse_stat_start_time("garbage"), None);
        assert!(proc_start_time(std::process::id() as i32).is_some());
    }

    #[test]
    fn atomic_write_roundtrip() {
        let dir = std::env::temp_dir().join(format!("hull-ut-{}", random_id()));
        let p = dir.join("x.json");
        atomic_write(&p, b"one").unwrap();
        atomic_write(&p, b"two").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "two");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ago_formats() {
        assert_eq!(ago(100, 105), "5s ago");
        assert_eq!(ago(0, 120), "2m ago");
        assert_eq!(ago(0, 7200), "2h ago");
        assert_eq!(ago(0, 172800), "2d ago");
        assert_eq!(ago(10, 5), "0s ago");
    }

    proptest::proptest! {
        #[test]
        fn size_format_roundtrip(v in 1u64..(1u64 << 50)) {
            proptest::prop_assert_eq!(parse_size(&format_size(v)).unwrap(), v);
        }

        #[test]
        fn cpus_roundtrip(milli in 1u64..1_000_000) {
            let s = format!("{}.{:03}", milli / 1000, milli % 1000);
            proptest::prop_assert_eq!(parse_cpus(&s).unwrap(), milli);
        }

        #[test]
        fn parse_size_never_panics(s in ".{0,20}") {
            let _ = parse_size(&s);
            let _ = parse_cpus(&s);
        }
    }
}

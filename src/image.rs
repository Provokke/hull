//! Content-addressed image store.
//!
//! ```text
//! <root>/images/blobs/sha256/<hex>        original tarball (as imported)
//! <root>/images/layers/<hex>/rootfs/      unpacked root filesystem (overlay lowerdir)
//! <root>/images/layers/<hex>/meta.json    size, source, creation time
//! <root>/images/refs.json                 { "alpine": "sha256:<hex>", ... }
//! ```

use crate::util::{atomic_write, now_secs};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageMeta {
    pub digest: String,
    pub size: u64,
    pub created: u64,
    pub source: String,
}

pub struct Store {
    pub root: PathBuf,
}

/// Validate a digest string ("sha256:" + 64 lowercase hex chars).
pub fn valid_digest(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')))
}

pub fn valid_ref_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 128
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
        && !n.starts_with('.')
}

fn sha256_file(p: &Path) -> io::Result<(String, u64)> {
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut n = 0u64;
    loop {
        let r = f.read(&mut buf)?;
        if r == 0 {
            break;
        }
        n += r as u64;
        h.update(&buf[..r]);
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Ok((format!("sha256:{hex}"), n))
}

impl Store {
    pub fn new(root: &Path) -> Self {
        Store {
            root: root.join("images"),
        }
    }

    fn refs_path(&self) -> PathBuf {
        self.root.join("refs.json")
    }

    pub fn refs(&self) -> BTreeMap<String, String> {
        fs::read(self.refs_path())
            .ok()
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default()
    }

    fn set_ref(&self, name: &str, digest: &str) -> io::Result<()> {
        let mut r = self.refs();
        r.insert(name.to_string(), digest.to_string());
        atomic_write(&self.refs_path(), &serde_json::to_vec_pretty(&r)?)
    }

    pub fn layer_dir(&self, digest: &str) -> PathBuf {
        self.root
            .join("layers")
            .join(digest.trim_start_matches("sha256:"))
    }

    pub fn rootfs(&self, digest: &str) -> PathBuf {
        self.layer_dir(digest).join("rootfs")
    }

    pub fn meta(&self, digest: &str) -> Option<ImageMeta> {
        let d = fs::read(self.layer_dir(digest).join("meta.json")).ok()?;
        serde_json::from_slice(&d).ok()
    }

    /// Resolve a name or digest (or unique digest prefix) to a full digest.
    pub fn resolve(&self, r: &str) -> Result<String, String> {
        if let Some(d) = self.refs().get(r) {
            return Ok(d.clone());
        }
        let want = r.trim_start_matches("sha256:");
        if want.len() >= 6 {
            let mut hits = vec![];
            if let Ok(rd) = fs::read_dir(self.root.join("layers")) {
                for e in rd.flatten() {
                    let n = e.file_name().to_string_lossy().to_string();
                    if n.starts_with(want) && e.path().join("meta.json").exists() {
                        hits.push(format!("sha256:{n}"));
                    }
                }
            }
            if hits.len() == 1 {
                return Ok(hits.remove(0));
            }
        }
        Err(format!(
            "image '{r}' not found (try `hull pull alpine` or `hull import`)"
        ))
    }

    /// Import a (optionally gzip compressed) rootfs tarball under `name`.
    /// Identical tarballs are stored once.
    pub fn import(&self, tar_path: &Path, name: &str, source: &str) -> io::Result<String> {
        if !valid_ref_name(name) {
            return Err(io::Error::other(format!("invalid image name '{name}'")));
        }
        let (digest, size) = sha256_file(tar_path)?;
        let hex = digest.trim_start_matches("sha256:").to_string();
        let layer = self.layer_dir(&digest);
        if !layer.join("meta.json").exists() {
            let blob_dir = self.root.join("blobs/sha256");
            fs::create_dir_all(&blob_dir)?;
            fs::copy(tar_path, blob_dir.join(&hex))?;
            // Unpack into a temp dir then rename so a crash never leaves a
            // half-unpacked layer that looks valid.
            let tmp = self.root.join("layers").join(format!(".tmp-{hex}"));
            let _ = fs::remove_dir_all(&tmp);
            fs::create_dir_all(tmp.join("rootfs"))?;
            unpack(tar_path, &tmp.join("rootfs"))?;
            let meta = ImageMeta {
                digest: digest.clone(),
                size,
                created: now_secs(),
                source: source.to_string(),
            };
            atomic_write(&tmp.join("meta.json"), &serde_json::to_vec_pretty(&meta)?)?;
            let _ = fs::remove_dir_all(&layer);
            fs::rename(&tmp, &layer)?;
        }
        self.set_ref(name, &digest)?;
        Ok(digest)
    }

    pub fn list(&self) -> Vec<(String, ImageMeta)> {
        self.refs()
            .into_iter()
            .filter_map(|(n, d)| self.meta(&d).map(|m| (n, m)))
            .collect()
    }
}

/// Unpack a tar or tar.gz safely (the tar crate refuses entries escaping `dst`).
pub fn unpack(tar_path: &Path, dst: &Path) -> io::Result<()> {
    let mut f = fs::File::open(tar_path)?;
    let mut magic = [0u8; 2];
    let n = f.read(&mut magic)?;
    drop(f);
    let f = fs::File::open(tar_path)?;
    let reader: Box<dyn Read> = if n == 2 && magic == [0x1f, 0x8b] {
        Box::new(flate2::read::GzDecoder::new(f))
    } else {
        Box::new(f)
    };
    let mut ar = tar::Archive::new(reader);
    ar.set_preserve_permissions(true);
    ar.set_preserve_ownerships(true);
    ar.set_unpack_xattrs(false);
    ar.set_overwrite(true);
    ar.unpack(dst)
}

/// Build a deterministic rootfs tarball around a static busybox binary.
/// The output is byte-for-byte reproducible (fixed mtimes, sorted entries),
/// so importing it twice yields the same digest.
pub fn build_busybox_tar(busybox: &Path, out: &Path) -> io::Result<()> {
    let bin = fs::read(busybox)?;
    let list = Command::new(busybox).arg("--list-full").output()?;
    if !list.status.success() {
        return Err(io::Error::other("busybox --list-full failed"));
    }
    let mut applets: Vec<String> = String::from_utf8_lossy(&list.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.contains("..") && l != "bin/busybox")
        .collect();
    applets.sort();
    applets.dedup();

    let f = fs::File::create(out)?;
    let mut b = tar::Builder::new(f);
    let dir = |b: &mut tar::Builder<fs::File>, p: &str, mode: u32| -> io::Result<()> {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(mode);
        h.set_size(0);
        h.set_mtime(0);
        h.set_uid(0);
        h.set_gid(0);
        h.set_cksum();
        b.append_data(&mut h, p, io::empty())
    };
    for d in [
        "bin", "dev", "etc", "home", "proc", "root", "sbin", "sys", "tmp", "usr", "usr/bin",
        "usr/sbin", "var", "var/tmp", "mnt",
    ] {
        let mode = if d == "tmp" || d == "var/tmp" {
            0o1777
        } else if d == "root" {
            0o700
        } else {
            0o755
        };
        dir(&mut b, d, mode)?;
    }
    let file =
        |b: &mut tar::Builder<fs::File>, p: &str, data: &[u8], mode: u32| -> io::Result<()> {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_mode(mode);
            h.set_size(data.len() as u64);
            h.set_mtime(0);
            h.set_uid(0);
            h.set_gid(0);
            h.set_cksum();
            b.append_data(&mut h, p, data)
        };
    file(&mut b, "bin/busybox", &bin, 0o755)?;
    file(
        &mut b,
        "etc/passwd",
        b"root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n",
        0o644,
    )?;
    file(&mut b, "etc/group", b"root:x:0:\nnogroup:x:65534:\n", 0o644)?;
    file(
        &mut b,
        "etc/os-release",
        b"NAME=\"hull busybox rootfs\"\nID=busybox\n",
        0o644,
    )?;
    file(&mut b, "etc/hosts", b"127.0.0.1 localhost\n", 0o644)?;
    for a in &applets {
        // e.g. "usr/bin/wget" -> symlink to /bin/busybox
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_mode(0o777);
        h.set_size(0);
        h.set_mtime(0);
        h.set_uid(0);
        h.set_gid(0);
        h.set_cksum();
        b.append_link(&mut h, a, "/bin/busybox")?;
    }
    b.into_inner()?.flush()
}

/// Alpine minirootfs URL for the host architecture.
pub fn alpine_url() -> String {
    let arch = std::env::consts::ARCH;
    format!(
        "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/{arch}/alpine-minirootfs-3.20.3-{arch}.tar.gz"
    )
}

/// `hull pull`: try the Alpine CDN, fall back to a busybox-static rootfs.
pub fn pull(
    store: &Store,
    name: &str,
    busybox_only: bool,
    tmpdir: &Path,
) -> Result<String, String> {
    fs::create_dir_all(tmpdir).map_err(|e| e.to_string())?;
    let tmp = tmpdir.join(format!("pull-{}.tar", crate::util::random_id()));
    let res = (|| {
        if name.starts_with("alpine") && !busybox_only {
            let url = alpine_url();
            eprintln!("hull: downloading {url}");
            let out = Command::new("curl")
                .args(["-fsSL", "--max-time", "60", "-o"])
                .arg(&tmp)
                .arg(&url)
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    return store
                        .import(&tmp, name, &format!("download:{url}"))
                        .map_err(|e| e.to_string());
                }
                Ok(o) => eprintln!(
                    "hull: alpine CDN unreachable ({}); falling back to busybox-static rootfs",
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
                Err(e) => {
                    eprintln!("hull: curl unavailable ({e}); falling back to busybox-static rootfs")
                }
            }
        } else if name != "busybox" && !busybox_only {
            return Err(format!("unknown image '{name}': only 'alpine' and 'busybox' can be pulled; use `hull import`"));
        }
        let bb = ["/bin/busybox", "/usr/bin/busybox"]
            .iter()
            .map(Path::new)
            .find(|p| p.exists())
            .ok_or("busybox not found; install it with `apt-get install -y busybox-static`")?;
        build_busybox_tar(bb, &tmp).map_err(|e| e.to_string())?;
        store
            .import(&tmp, name, &format!("busybox-static:{}", bb.display()))
            .map_err(|e| e.to_string())
    })();
    let _ = fs::remove_file(&tmp);
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::random_id;

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!("hull-img-ut-{}", random_id()))
    }

    fn make_tar(path: &Path, files: &[(&str, &[u8])]) {
        let f = fs::File::create(path).unwrap();
        let mut b = tar::Builder::new(f);
        for (n, d) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(d.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(0);
            h.set_uid(0);
            h.set_gid(0);
            h.set_cksum();
            b.append_data(&mut h, n, *d).unwrap();
        }
        b.finish().unwrap();
    }

    #[test]
    fn import_is_content_addressed() {
        let root = tmp();
        let s = Store::new(&root);
        let t = root.join("a.tar");
        fs::create_dir_all(&root).unwrap();
        make_tar(&t, &[("etc/hello", b"world")]);
        let d1 = s.import(&t, "one", "test").unwrap();
        let d2 = s.import(&t, "two", "test").unwrap();
        assert_eq!(d1, d2);
        assert!(valid_digest(&d1));
        assert_eq!(
            fs::read_to_string(s.rootfs(&d1).join("etc/hello")).unwrap(),
            "world"
        );
        assert_eq!(s.resolve("one").unwrap(), d1);
        assert_eq!(s.resolve(&d1).unwrap(), d1);
        assert_eq!(s.resolve(&d1[7..19]).unwrap(), d1, "prefix lookup");
        assert!(s.resolve("nope").is_err());
        assert_eq!(s.list().len(), 2);
        // blob stored under its own digest
        let (bd, _) = sha256_file(&root.join("images/blobs/sha256").join(&d1[7..])).unwrap();
        assert_eq!(bd, d1);
        // different content -> different digest
        let t2 = root.join("b.tar");
        make_tar(&t2, &[("etc/hello", b"other")]);
        assert_ne!(s.import(&t2, "one", "test").unwrap(), d1);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gzip_import() {
        let root = tmp();
        fs::create_dir_all(&root).unwrap();
        let t = root.join("a.tar");
        make_tar(&t, &[("x", b"gz")]);
        let gz = root.join("a.tar.gz");
        let mut enc = flate2::write::GzEncoder::new(
            fs::File::create(&gz).unwrap(),
            flate2::Compression::fast(),
        );
        enc.write_all(&fs::read(&t).unwrap()).unwrap();
        enc.finish().unwrap();
        let s = Store::new(&root);
        let d = s.import(&gz, "gz", "t").unwrap();
        assert_eq!(fs::read_to_string(s.rootfs(&d).join("x")).unwrap(), "gz");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn path_traversal_is_contained() {
        let root = tmp();
        fs::create_dir_all(&root).unwrap();
        let t = root.join("evil.tar");
        // Build a tar with a "../escape" entry by writing the raw header name.
        let f = fs::File::create(&t).unwrap();
        let mut b = tar::Builder::new(f);
        let mut h = tar::Header::new_old();
        h.as_old_mut().name[..9].copy_from_slice(b"../escape");
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        b.append(&h, &b"x"[..]).unwrap();
        b.finish().unwrap();
        let s = Store::new(&root);
        let _ = s.import(&t, "evil", "t");
        assert!(!root.join("images/layers/escape").exists());
        assert!(!root.join("images/escape").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn names_and_digests() {
        assert!(valid_ref_name("alpine"));
        assert!(valid_ref_name("alpine:3.20"));
        assert!(!valid_ref_name("../x"));
        assert!(!valid_ref_name(""));
        assert!(!valid_ref_name(".hidden"));
        assert!(!valid_digest("sha256:abc"));
        assert!(valid_digest(&format!("sha256:{}", "a".repeat(64))));
    }

    #[test]
    fn busybox_tar_is_reproducible() {
        let bb = Path::new("/bin/busybox");
        if !bb.exists() {
            eprintln!("skipping: /bin/busybox not installed");
            return;
        }
        let root = tmp();
        fs::create_dir_all(&root).unwrap();
        build_busybox_tar(bb, &root.join("1.tar")).unwrap();
        build_busybox_tar(bb, &root.join("2.tar")).unwrap();
        assert_eq!(
            sha256_file(&root.join("1.tar")).unwrap(),
            sha256_file(&root.join("2.tar")).unwrap()
        );
        let s = Store::new(&root);
        let d = s.import(&root.join("1.tar"), "busybox", "t").unwrap();
        let rf = s.rootfs(&d);
        assert!(rf.join("bin/busybox").is_file());
        assert_eq!(
            fs::read_link(rf.join("bin/sh")).unwrap(),
            Path::new("/bin/busybox")
        );
        fs::remove_dir_all(&root).unwrap();
    }
}

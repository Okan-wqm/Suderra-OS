// SPDX-FileCopyrightText: 2026 Suderra OS contributors
// SPDX-License-Identifier: Apache-2.0

//! Filesystem primitives of the root installer (ADR-048 DEC-1.4, DEC-1.10,
//! DEC-2.3, DEC-4.3).
//!
//! Root writes only into root-owned trees, with exclusive temporary names,
//! fsync and `rename(2)`; it never follows a symlink it did not create. Files
//! the agent wrote are read through an `openat(O_NOFOLLOW)` walk from `/` with
//! a regular-file and size check, so an agent-planted symlink, FIFO or huge
//! file is refused.

use anyhow::{bail, Context, Result};
use nix::fcntl::{openat, OFlag};
use nix::sys::stat::{fstat, Mode, SFlag};
use nix::unistd::Gid;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::RawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

/// A raw descriptor closed on drop (nix 0.29 hands out `RawFd`).
struct Fd(RawFd);

impl Drop for Fd {
    fn drop(&mut self) {
        // A close error on a read-only descriptor loses nothing.
        let _ = nix::unistd::close(self.0);
    }
}

/// `N` bytes from the kernel CSPRNG.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0_u8; N];
    getrandom::getrandom(&mut out).map_err(|e| anyhow::anyhow!("CSPRNG unavailable: {e}"))?;
    Ok(out)
}

/// A unique temporary name in the same directory.
fn temp_name(name: &str) -> Result<String> {
    Ok(format!(".{name}.tmp-{}", hex::encode(random_bytes::<8>()?)))
}

fn file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{} has no UTF-8 file name", path.display()))
}

fn parent(path: &Path) -> Result<&Path> {
    path.parent()
        .with_context(|| format!("{} has no parent", path.display()))
}

/// fsyncs a directory so a rename in it is durable.
pub(crate) fn fsync_dir(dir: &Path) -> Result<()> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("cannot fsync {}", dir.display()))
}

/// Creates `dir` (and missing parents) and requires a real directory owned
/// by the caller with exactly `mode`.
pub(crate) fn ensure_dir(dir: &Path, mode: u32) -> Result<()> {
    if fs::symlink_metadata(dir).is_err() {
        if let Some(up) = dir.parent() {
            if !up.as_os_str().is_empty() && fs::symlink_metadata(up).is_err() {
                ensure_dir(up, 0o755)?;
            }
        }
        match fs::create_dir(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("cannot create {}", dir.display())),
        }
        fs::set_permissions(dir, fs::Permissions::from_mode(mode))
            .with_context(|| format!("cannot chmod {}", dir.display()))?;
    }
    let meta =
        fs::symlink_metadata(dir).with_context(|| format!("cannot stat {}", dir.display()))?;
    if !meta.file_type().is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    if meta.uid() != nix::unistd::geteuid().as_raw() {
        bail!("{} is not owned by the installer's user", dir.display());
    }
    if meta.mode() & 0o7777 != mode {
        fs::set_permissions(dir, fs::Permissions::from_mode(mode))
            .with_context(|| format!("cannot chmod {}", dir.display()))?;
    }
    Ok(())
}

/// Writes `bytes` to `path` atomically: exclusive temporary file, fsync,
/// `rename(2)`, fsync of the directory. `group` sets the file's group for
/// files the agent reads (root:suderra).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], mode: u32, group: Option<Gid>) -> Result<()> {
    let dir = parent(path)?;
    let tmp = dir.join(temp_name(file_name(path)?)?);
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc_flags::O_NOFOLLOW | libc_flags::O_CLOEXEC)
            .open(&tmp)
            .with_context(|| format!("cannot create {}", tmp.display()))?;
        if let Some(gid) = group {
            std::os::unix::fs::fchown(&file, None, Some(gid.as_raw()))
                .with_context(|| format!("cannot chgrp {}", tmp.display()))?;
        }
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
            .with_context(|| format!("cannot rename {} to {}", tmp.display(), path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    fsync_dir(dir)
}

/// Points the symlink `link` at `target` atomically: a temporary symlink
/// renamed over `link` (never `ln -sfn`, which leaves a window without a link).
pub(crate) fn symlink_atomic(target: &Path, link: &Path) -> Result<()> {
    let dir = parent(link)?;
    let tmp = dir.join(temp_name(file_name(link)?)?);
    std::os::unix::fs::symlink(target, &tmp)
        .with_context(|| format!("cannot create {}", tmp.display()))?;
    if let Err(e) = fs::rename(&tmp, link) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("cannot switch {}", link.display()));
    }
    fsync_dir(dir)
}

/// Reads a root-owned file without following a final symlink; `None` when it
/// does not exist.
pub(crate) fn read_root_file(path: &Path, max: u64) -> Result<Option<Vec<u8>>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc_flags::O_NOFOLLOW | libc_flags::O_CLOEXEC | libc_flags::O_NONBLOCK)
        .open(path)
    {
        Ok(mut file) => {
            let meta = file.metadata()?;
            if !meta.file_type().is_file() {
                bail!("{} is not a regular file", path.display());
            }
            if meta.len() > max {
                bail!("{} exceeds {max} bytes", path.display());
            }
            let mut out = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
            std::io::Read::read_to_end(&mut (&mut file).take(max + 1), &mut out)?;
            if u64::try_from(out.len()).unwrap_or(u64::MAX) > max {
                bail!("{} exceeds {max} bytes", path.display());
            }
            Ok(Some(out))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot open {}", path.display())),
    }
}

use std::io::Read as _;

/// Reads a file from a tree another principal can write (the agent's state
/// directory): every component is opened with `O_NOFOLLOW` relative to the
/// previous one, the final one must be a regular file of at most `max`
/// bytes. `None` when it does not exist.
pub(crate) fn read_untrusted_file(path: &Path, max: u64) -> Result<Option<Vec<u8>>> {
    if !path.is_absolute() {
        bail!("{} is not absolute", path.display());
    }
    let mut components: Vec<&std::ffi::OsStr> = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name),
            _ => bail!("{} is not a normal path", path.display()),
        }
    }
    let Some((last, dirs)) = components.split_last() else {
        bail!("{} names no file", path.display());
    };
    let dir_flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut dir =
        Fd(openat(None, "/", dir_flags, Mode::empty())
            .with_context(|| "cannot open /".to_owned())?);
    for name in dirs {
        match openat(Some(dir.0), *name, dir_flags, Mode::empty()) {
            Ok(fd) => dir = Fd(fd),
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("{}: a component is not a real directory", path.display())
                })
            }
        }
    }
    let file_flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
    let file = match openat(Some(dir.0), *last, file_flags, Mode::empty()) {
        Ok(fd) => Fd(fd),
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("{} cannot be opened as a regular file", path.display()))
        }
    };
    let stat = fstat(file.0).with_context(|| format!("cannot stat {}", path.display()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG {
        bail!("{} is not a regular file", path.display());
    }
    if u64::try_from(stat.st_size).unwrap_or(u64::MAX) > max {
        bail!("{} exceeds {max} bytes", path.display());
    }
    let mut out = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        let n = nix::unistd::read(file.0, &mut buf)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if u64::try_from(out.len()).unwrap_or(u64::MAX) > max {
            bail!("{} exceeds {max} bytes", path.display());
        }
    }
    Ok(Some(out))
}

/// Flags not exposed by std.
pub(crate) mod libc_flags {
    /// O_NOFOLLOW.
    pub const O_NOFOLLOW: i32 = nix::libc::O_NOFOLLOW;
    /// O_CLOEXEC.
    pub const O_CLOEXEC: i32 = nix::libc::O_CLOEXEC;
    /// O_NONBLOCK.
    pub const O_NONBLOCK: i32 = nix::libc::O_NONBLOCK;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_and_leaves_no_temporary() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("state.json");
        write_atomic(&path, b"one", 0o600, None).unwrap();
        write_atomic(&path, b"two", 0o600, None).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 1);
    }

    #[test]
    fn symlink_switch_is_a_rename() {
        let tmp = tempfile::TempDir::new().unwrap();
        let link = tmp.path().join("current");
        symlink_atomic(Path::new("releases/1.0.0"), &link).unwrap();
        symlink_atomic(Path::new("releases/1.1.0"), &link).unwrap();
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("releases/1.1.0"));
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 1);
    }

    #[test]
    fn untrusted_reads_refuse_symlinks_fifos_and_oversize() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let state = root.join("state");
        fs::create_dir(&state).unwrap();
        fs::write(state.join("ok.dsse"), b"{}").unwrap();
        assert_eq!(
            read_untrusted_file(&state.join("ok.dsse"), 16)
                .unwrap()
                .unwrap(),
            b"{}"
        );
        assert!(read_untrusted_file(&state.join("missing"), 16)
            .unwrap()
            .is_none());
        assert!(read_untrusted_file(&state.join("ok.dsse"), 1).is_err());

        fs::write(root.join("secret"), b"root only").unwrap();
        std::os::unix::fs::symlink(root.join("secret"), state.join("link.dsse")).unwrap();
        assert!(read_untrusted_file(&state.join("link.dsse"), 64).is_err());

        // A symlinked intermediate directory is refused too.
        std::os::unix::fs::symlink(&state, root.join("state-link")).unwrap();
        assert!(read_untrusted_file(&root.join("state-link/ok.dsse"), 64).is_err());

        nix::unistd::mkfifo(&state.join("fifo.dsse"), Mode::from_bits_truncate(0o600)).unwrap();
        assert!(read_untrusted_file(&state.join("fifo.dsse"), 64).is_err());
    }

    #[test]
    fn root_reads_refuse_a_final_symlink() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(tmp.path().join("real"), b"x").unwrap();
        std::os::unix::fs::symlink(tmp.path().join("real"), tmp.path().join("link")).unwrap();
        assert!(read_root_file(&tmp.path().join("link"), 8).is_err());
        assert_eq!(
            read_root_file(&tmp.path().join("real"), 8)
                .unwrap()
                .unwrap(),
            b"x"
        );
        assert!(read_root_file(&tmp.path().join("none"), 8)
            .unwrap()
            .is_none());
    }
}

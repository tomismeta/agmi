//! Stable protocol-1 routing and lifetime lease; the installer owns payload semantics.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::os::{
    fd::{AsRawFd, FromRawFd},
    unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
};
use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    rc::{Rc, Weak},
    sync::atomic::{AtomicU64, Ordering},
};

const RECORD: &str = ".update-state.json";
const CHILD_FD: &str = "AGMI_UPDATE_LEASE_FD";
const CHILD_NONCE: &str = "AGMI_UPDATE_LEASE_NONCE";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
thread_local! { static OWNED: RefCell<Vec<(PathBuf, Weak<File>)>> = const { RefCell::new(Vec::new()) }; }

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Header {
    pub format: u32,
    pub protocol: u32,
    pub nonce: String,
    pub root: PathBuf,
    pub config: PathBuf,
    pub source: String,
    pub target: String,
    pub digest: String,
    pub embedded_sha256: String,
    pub payload_format: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub header: Header,
    // Stable cancellation bit is outside the opaque target-owned payload.
    pub cancelled: bool,
    pub payload: Value,
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn release(value: &str) -> bool {
    value.strip_prefix("r-").is_some_and(|v| hex(v, 64))
}
fn private(file: &File) -> Result<()> {
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o777 == 0o600
            && m.nlink() == 1,
        "update state is not a private account-owned regular file"
    );
    Ok(())
}
pub(crate) fn read(root: &Path) -> Result<Option<Record>> {
    let path = root.join(RECORD);
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    private(&file)?;
    ensure!(
        file.metadata()?.len() <= 65536,
        "update record exceeds protocol bound"
    );
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "update record exceeds protocol bound");
    let record: Record = serde_json::from_slice(&bytes)?;
    let h = &record.header;
    ensure!(
        h.format == 1
            && h.protocol == 1
            && hex(&h.nonce, 64)
            && release(&h.source)
            && release(&h.target)
            && h.digest == h.target[2..]
            && hex(&h.embedded_sha256, 64)
            && h.payload_format > 0,
        "unsupported update routing header"
    );
    ensure!(
        h.root == fs::canonicalize(root)?,
        "update record belongs to another installation"
    );
    Ok(Some(record))
}
pub(crate) fn save(root: &Path, record: &Record) -> Result<()> {
    if let Some(old) = read(root)? {
        ensure!(
            serde_json::to_value(&old.header)? == serde_json::to_value(&record.header)?,
            "immutable update route changed"
        );
        ensure!(
            !old.cancelled || record.cancelled,
            "cancelled restoration cannot be revived"
        );
    }
    let bytes = serde_json::to_vec(record)?;
    ensure!(bytes.len() <= 65536, "update record exceeds protocol bound");
    let (temporary, mut file) = (0..1000)
        .find_map(|_| {
            let path = root.join(format!(
                ".update-state.{}.{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
            {
                Ok(file) => Some(Ok((path, file))),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error)),
            }
        })
        .context("cannot allocate private update record")??;
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, root.join(RECORD))?;
        File::open(root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
pub(crate) fn remove(root: &Path, nonce: &str) -> Result<()> {
    let record = read(root)?.context("update record disappeared")?;
    ensure!(record.header.nonce == nonce, "update record replaced");
    fs::remove_file(root.join(RECORD))?;
    File::open(root)?.sync_all()?;
    Ok(())
}

pub(crate) struct Lease {
    file: Rc<File>,
    pub inherited: bool,
}
impl Lease {
    pub fn acquire(root: &Path) -> Result<Self> {
        Self::acquire_inner(root, false)
    }
    pub fn acquire_or_reuse(root: &Path) -> Result<Self> {
        Self::acquire_inner(root, true)
    }
    fn acquire_inner(root: &Path, reuse: bool) -> Result<Self> {
        let root = fs::canonicalize(root)?;
        let path = root.join(".install-lock");
        if fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
            return Err(super::installer_preflight_error("legacy_install_lock"));
        }
        if reuse
            && let Some(file) = OWNED.with(|owned| {
                owned
                    .borrow()
                    .iter()
                    .find_map(|(p, f)| (p == &path).then(|| f.upgrade()).flatten())
            })
        {
            return Ok(Self {
                file,
                inherited: true,
            });
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)?;
        private(&file)?;
        let m = file.metadata()?;
        let observed = fs::symlink_metadata(&path)?;
        ensure!(
            (m.dev(), m.ino()) == (observed.dev(), observed.ino()),
            "install lease inode changed"
        );
        let mut inherited = false;
        let file = if let Ok(fd) = std::env::var(CHILD_FD) {
            let fd: i32 = fd.parse()?;
            ensure!(fd >= 3, "invalid inherited lease");
            let record = read(&root)?.context("inherited lease has no transaction")?;
            ensure!(
                std::env::var(CHILD_NONCE).ok().as_deref() == Some(&record.header.nonce),
                "inherited lease transaction changed"
            );
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            ensure!(duplicate >= 0, "inherited lease descriptor unavailable");
            let inherited_file = unsafe { File::from_raw_fd(duplicate) };
            let im = inherited_file.metadata()?;
            ensure!(
                (im.dev(), im.ino()) == (m.dev(), m.ino()),
                "inherited lease inode mismatch"
            );
            ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0,
                "inherited lease is not held"
            );
            ensure!(
                unsafe { libc::flock(inherited_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }
                    == 0,
                "inherited lease is not its owner"
            );
            // Close the non-CLOEXEC inherited copy before this CLI can launch any children.
            unsafe {
                libc::close(fd);
            }
            inherited = true;
            inherited_file
        } else {
            ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                super::installer_preflight_error("update_in_progress")
            );
            file
        };
        let file = Rc::new(file);
        let held = file.metadata()?;
        let selected = fs::symlink_metadata(&path)?;
        ensure!(
            (held.dev(), held.ino()) == (selected.dev(), selected.ino()) && selected.is_file(),
            "install lease inode changed while acquiring ownership"
        );
        OWNED.with(|owned| {
            let mut owned = owned.borrow_mut();
            owned.retain(|(_, f)| f.strong_count() > 0);
            owned.push((path, Rc::downgrade(&file)));
        });
        Ok(Self { file, inherited })
    }
    pub fn inherit(&self, command: &mut std::process::Command, nonce: &str) -> Result<()> {
        let fd = self.file.as_raw_fd();
        command
            .env(CHILD_FD, fd.to_string())
            .env(CHILD_NONCE, nonce);
        // Only the forked control child clears CLOEXEC. Parent/runtime descriptors remain private.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lease_keeps_inode_and_refuses_legacy_directory() -> Result<()> {
        let root = tempfile::tempdir()?;
        let lease = Lease::acquire(root.path())?;
        let inode = fs::metadata(root.path().join(".install-lock"))?.ino();
        drop(lease);
        let lease = Lease::acquire(root.path())?;
        assert_eq!(
            fs::metadata(root.path().join(".install-lock"))?.ino(),
            inode
        );
        drop(lease);
        let old = tempfile::tempdir()?;
        fs::create_dir(old.path().join(".install-lock"))?;
        assert!(Lease::acquire(old.path()).is_err());
        Ok(())
    }
    fn fixture_record(root: &Path) -> Record {
        Record {
            header: Header {
                format: 1,
                protocol: 1,
                nonce: "a".repeat(64),
                root: fs::canonicalize(root).unwrap(),
                config: root.join("config.toml"),
                source: format!("r-{}", "b".repeat(64)),
                target: format!("r-{}", "c".repeat(64)),
                digest: "c".repeat(64),
                embedded_sha256: "d".repeat(64),
                payload_format: 99,
            },
            cancelled: false,
            payload: serde_json::json!({"future_owned_payload":["opaque"]}),
        }
    }
    #[test]
    fn routing_preserves_opaque_payload_and_durable_cancellation() -> Result<()> {
        let root = tempfile::tempdir()?;
        let record = fixture_record(root.path());
        save(root.path(), &record)?;
        let mut observed = read(root.path())?.unwrap();
        assert_eq!(observed.payload, record.payload);
        observed.cancelled = true;
        save(root.path(), &observed)?;
        assert!(save(root.path(), &record).is_err());
        observed.header.target = format!("r-{}", "e".repeat(64));
        assert!(save(root.path(), &observed).is_err());
        assert_eq!(
            fs::metadata(root.path().join(RECORD))?.mode() & 0o777,
            0o600
        );
        Ok(())
    }
    #[test]
    fn inherited_lease_child() -> Result<()> {
        let Some(root) = std::env::var_os("AGMI_LEASE_TEST_ROOT") else {
            return Ok(());
        };
        let root = PathBuf::from(root);
        let lease = Lease::acquire(&root)?;
        assert!(lease.inherited);
        fs::write(root.join("child-ready"), b"ready")?;
        let mut byte = [0];
        std::io::stdin().read_exact(&mut byte)?;
        drop(lease);
        Ok(())
    }
    #[test]
    fn inherited_child_keeps_kernel_ownership_after_parent_drops() -> Result<()> {
        use std::process::{Command, Stdio};
        let root = tempfile::tempdir()?;
        let record = fixture_record(root.path());
        save(root.path(), &record)?;
        let lease = Lease::acquire(root.path())?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "lifecycle::update_state::tests::inherited_lease_child",
                "--nocapture",
            ])
            .env("AGMI_LEASE_TEST_ROOT", root.path())
            .stdin(Stdio::piped());
        lease.inherit(&mut command, &record.header.nonce)?;
        let mut child = command.spawn()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !root.path().join("child-ready").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !root.path().join("child-ready").exists() {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("inherited control child did not acquire its lease");
        }
        drop(lease);
        assert!(Lease::acquire(root.path()).is_err());
        child.stdin.take().unwrap().write_all(b"x")?;
        assert!(child.wait()?.success());
        let _released = Lease::acquire(root.path())?;
        Ok(())
    }
}

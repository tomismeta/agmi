//! Shared bounded, symlink-safe regular-file and atomic-write primitives.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering, compiler_fence};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Best-effort volatile scrub of sensitive bytes in memory.
pub(crate) fn wipe_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Owned sensitive byte buffer that scrubs its storage on drop.
pub(crate) struct ScrubBytes(pub(crate) Vec<u8>);

impl Drop for ScrubBytes {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegularReadError {
    NotFound,
    UnsafeFile,
    TooLarge,
    Io,
}

fn map_open_error(error: io::Error) -> RegularReadError {
    if error.kind() == io::ErrorKind::NotFound {
        return RegularReadError::NotFound;
    }
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ELOOP) {
        return RegularReadError::UnsafeFile;
    }
    if error.kind() == io::ErrorKind::InvalidInput {
        return RegularReadError::UnsafeFile;
    }
    RegularReadError::Io
}

/// Open and read a regular file without following a final symlink or blocking on FIFOs.
/// Verifies ownership, single hardlink, regular file type, optional 0600 privacy, and size bound.
pub fn read_bounded_regular(
    path: &Path,
    max_bytes: usize,
    require_private: bool,
) -> Result<Vec<u8>, RegularReadError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_regular_metadata(&metadata, require_private)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(RegularReadError::NotFound);
        }
        Err(_) => return Err(RegularReadError::Io),
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(map_open_error)?;
    let metadata = file.metadata().map_err(|_| RegularReadError::Io)?;
    validate_regular_metadata(&metadata, require_private)?;
    if metadata.len() > max_bytes as u64 {
        return Err(RegularReadError::TooLarge);
    }
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(max_bytes));
    file.take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| RegularReadError::Io)?;
    if bytes.len() > max_bytes {
        return Err(RegularReadError::TooLarge);
    }
    Ok(bytes)
}

/// Read a bounded, non-private shared regular file (such as a system-installed
/// read-only network profile that may be root-owned or symlinked, e.g. in `/etc` or Nix).
/// Still uses `O_NONBLOCK | O_CLOEXEC`, verifies regular file type, and enforces `max_bytes`.
pub(crate) fn read_bounded_shared(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, RegularReadError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(map_open_error)?;
    let metadata = file.metadata().map_err(|_| RegularReadError::Io)?;
    if !metadata.is_file() {
        return Err(RegularReadError::UnsafeFile);
    }
    if metadata.len() > max_bytes as u64 {
        return Err(RegularReadError::TooLarge);
    }
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(max_bytes));
    file.take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| RegularReadError::Io)?;
    if bytes.len() > max_bytes {
        return Err(RegularReadError::TooLarge);
    }
    Ok(bytes)
}

pub(crate) fn validate_regular_metadata(
    metadata: &fs::Metadata,
    require_private: bool,
) -> Result<(), RegularReadError> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(RegularReadError::UnsafeFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || (require_private && metadata.mode() & 0o077 != 0)
        {
            return Err(RegularReadError::UnsafeFile);
        }
    }
    Ok(())
}

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    let dir = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    File::open(dir)?.sync_all()
}

struct TempGuard(PathBuf);
impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Atomically write a private 0600 file with fsync and parent-directory fsync.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8], prefix: &str) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let (guard, mut file) = loop {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let name = parent.join(format!(".{prefix}-{}-{serial}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        match options.open(&name) {
            Ok(file) => break (TempGuard(name), file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&guard.0, path)?;
    sync_directory(parent)?;
    Ok(())
}

/// Resolve symlinks component-by-component before collapsing `..` (including missing tails),
/// anchoring relative paths to `current_dir()`. Prevents `/dir/symlink/../file` bypasses of
/// path-overlap checks and resolves platform aliases like macOS `/var` -> `/private/var`.
pub(crate) fn canonicalize_existing_prefix(path: &Path) -> PathBuf {
    fn walk(path: &Path, resolved: &mut PathBuf, links: &mut usize) -> bool {
        for component in path.components() {
            match component {
                Component::RootDir => *resolved = PathBuf::from("/"),
                Component::CurDir => {}
                Component::ParentDir => {
                    resolved.pop();
                }
                Component::Normal(name) => {
                    resolved.push(name);
                    if let Ok(metadata) = fs::symlink_metadata(&resolved)
                        && metadata.file_type().is_symlink()
                    {
                        if *links >= 40 {
                            return false;
                        }
                        *links += 1;
                        let Ok(target) = fs::read_link(&resolved) else {
                            return false;
                        };
                        resolved.pop();
                        if !walk(&target, resolved, links) {
                            return false;
                        }
                    }
                }
                Component::Prefix(prefix) => resolved.push(prefix.as_os_str()),
            }
        }
        true
    }
    let anchored = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(path)
    } else {
        path.to_path_buf()
    };
    let mut resolved = PathBuf::new();
    let mut links = 0;
    if walk(&anchored, &mut resolved, &mut links) {
        resolved
    } else {
        anchored
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    #[test]
    fn read_bounded_regular_enforces_bounds_and_classifies_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.txt");
        assert_eq!(
            read_bounded_regular(&missing, 64, false).unwrap_err(),
            RegularReadError::NotFound
        );

        let file = dir.path().join("regular.txt");
        fs::write(&file, b"hello").unwrap();
        assert_eq!(read_bounded_regular(&file, 64, false).unwrap(), b"hello");
        assert_eq!(
            read_bounded_regular(&file, 4, false).unwrap_err(),
            RegularReadError::TooLarge
        );

        #[cfg(unix)]
        {
            fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(
                read_bounded_regular(&file, 64, true).unwrap_err(),
                RegularReadError::UnsafeFile
            );
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(read_bounded_regular(&file, 64, true).unwrap(), b"hello");

            let link = dir.path().join("link.txt");
            symlink(&file, &link).unwrap();
            assert_eq!(
                read_bounded_regular(&link, 64, false).unwrap_err(),
                RegularReadError::UnsafeFile
            );
            // Shared profiles intentionally allow symlinks while enforcing bounds.
            assert_eq!(read_bounded_shared(&link, 64).unwrap(), b"hello");
            assert_eq!(
                read_bounded_shared(&link, 4).unwrap_err(),
                RegularReadError::TooLarge
            );

            let hard = dir.path().join("hard.txt");
            fs::hard_link(&file, &hard).unwrap();
            assert_eq!(
                read_bounded_regular(&file, 64, false).unwrap_err(),
                RegularReadError::UnsafeFile
            );
            fs::remove_file(&hard).unwrap();

            // Unreadable regular file (mode 0000) must report Io, not UnsafeFile.
            let unreadable = dir.path().join("unreadable.txt");
            fs::write(&unreadable, b"secret").unwrap();
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
            if unsafe { libc::geteuid() } != 0 {
                assert_eq!(
                    read_bounded_regular(&unreadable, 64, false).unwrap_err(),
                    RegularReadError::Io
                );
            }
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn canonicalize_existing_prefix_resolves_symlinks_before_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let sub = state.join("sub");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&sub).unwrap();
        fs::create_dir_all(&outside).unwrap();
        #[cfg(unix)]
        {
            let link = outside.join("link");
            symlink(&sub, &link).unwrap();
            let resolved = canonicalize_existing_prefix(&link.join("../secret.md"));
            let canon_state = fs::canonicalize(&state).unwrap();
            assert_eq!(resolved, canon_state.join("secret.md"));
            assert!(resolved.starts_with(&canon_state));
        }
    }

    #[test]
    fn atomic_write_sets_private_mode_and_wipe_clears_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("saved.toml");
        atomic_write(&target, b"key = 1\n", "test").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"key = 1\n");
        #[cfg(unix)]
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o600);

        let mut buf = b"pk_secret_value".to_vec();
        wipe_bytes(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }
}

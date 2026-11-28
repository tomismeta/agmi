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

#[derive(Debug)]
pub enum RegularReadError {
    NotFound,
    UnsafeFile,
    TooLarge,
    Io,
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
    let file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            RegularReadError::NotFound
        } else {
            RegularReadError::UnsafeFile
        }
    })?;
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
    File::open(path)?.sync_all()
}

struct TempGuard(PathBuf);
impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Atomically write a private 0600 file with fsync and parent-directory fsync.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8], prefix: &str) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic write target has no parent",
        )
    })?;
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

/// Canonicalize the longest existing ancestor prefix of `path` and re-attach remaining
/// normalized components, so macOS `/var` -> `/private/var` aliases match before creation.
pub(crate) fn canonicalize_existing_prefix(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    let mut tail = Vec::new();
    let mut cursor = normalized.as_path();
    loop {
        if let Ok(canonical) = fs::canonicalize(cursor) {
            let mut result = canonical;
            for part in tail.into_iter().rev() {
                result.push(part);
            }
            return result;
        }
        let Some(name) = cursor.file_name() else {
            return normalized;
        };
        tail.push(name.to_os_string());
        let Some(parent) = cursor.parent() else {
            return normalized;
        };
        cursor = parent;
    }
}

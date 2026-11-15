use super::*;
use std::sync::{OnceLock, mpsc};

enum Cleanup {
    Remove(PathBuf),
    #[cfg(test)]
    Pause(tokio::sync::oneshot::Sender<()>, mpsc::Receiver<()>),
    Drain(tokio::sync::oneshot::Sender<std::io::Result<()>>),
}

// Shutdown must inspect an uninitialized worker without starting a thread on
// runs that never owned native scratch, hence the non-initializing OnceLock.
static WORKER: OnceLock<std::io::Result<mpsc::Sender<Cleanup>>> = OnceLock::new();
static OUTSTANDING: AtomicU64 = AtomicU64::new(0);

fn worker() -> Result<&'static mpsc::Sender<Cleanup>> {
    WORKER
        .get_or_init(|| {
            let (sender, receiver) = mpsc::channel();
            std::thread::Builder::new()
                .name("agmi-native-cleanup".into())
                .spawn(move || {
                    let mut failure = None;
                    for message in receiver {
                        match message {
                            Cleanup::Remove(path) => {
                                if let Err(error) = std::fs::remove_dir_all(path)
                                    && error.kind() != std::io::ErrorKind::NotFound
                                    && failure.is_none()
                                {
                                    failure = Some(error);
                                }
                                OUTSTANDING.fetch_sub(1, Ordering::Release);
                            }
                            Cleanup::Drain(reply) => {
                                let result = failure.take().map_or(Ok(()), Err);
                                if let Err(Err(error)) = reply.send(result) {
                                    failure = Some(error);
                                }
                            }
                            #[cfg(test)]
                            Cleanup::Pause(started, release) => {
                                let _ = started.send(());
                                let _ = release.recv();
                            }
                        }
                    }
                })
                .map(|_| sender)
        })
        .as_ref()
        .map_err(|error| anyhow::anyhow!("native cleanup worker unavailable: {error}"))
}

pub(crate) async fn drain_native_cleanup_until(deadline: tokio::time::Instant) -> Result<bool> {
    let Some(worker) = WORKER.get() else {
        return Ok(true);
    };
    let worker = worker
        .as_ref()
        .map_err(|error| anyhow::anyhow!("native cleanup worker unavailable: {error}"))?;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();
        worker
            .send(Cleanup::Drain(sender))
            .map_err(|_| anyhow::anyhow!("native cleanup worker stopped"))?;
        match tokio::time::timeout_at(deadline, receiver).await {
            Ok(result) => result.context("native cleanup acknowledgement lost")??,
            Err(_) => return Ok(false),
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        if OUTSTANDING.load(Ordering::Acquire) == 0 {
            return Ok(true);
        }
        // An aborted collector may still own its root when its join budget
        // expires. Do not acknowledge a clean drain ahead of that handoff.
        tokio::time::sleep_until(
            deadline.min(tokio::time::Instant::now() + Duration::from_millis(1)),
        )
        .await;
    }
}

/// Only workspace path resolution/allocation may construct this marker. Keep
/// the original OS error without exposing its path through the public code.
#[derive(Debug)]
pub(super) struct WorkspaceAllocationError(pub(super) std::io::Error);
impl WorkspaceAllocationError {
    pub(super) fn reason(&self) -> contract::NativeReasonCode {
        use contract::NativeReasonCode::*;
        match self.0.raw_os_error() {
            Some(libc::ENOENT | libc::ENOTDIR) => NativeWorkspaceUnavailable,
            Some(libc::ENOSPC | libc::EDQUOT) => NativeWorkspaceCapacity,
            Some(libc::EACCES | libc::EPERM | libc::EROFS) => NativeWorkspacePermission,
            _ => NativeWorkspaceFailure,
        }
    }
}
impl std::fmt::Display for WorkspaceAllocationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("cannot allocate isolated adapter workspace")
    }
}
impl std::error::Error for WorkspaceAllocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

pub(super) struct Scratch(pub(super) PathBuf, &'static mpsc::Sender<Cleanup>);
impl Scratch {
    pub(super) fn new() -> Result<Self> {
        Self::in_root(&std::env::temp_dir())
    }

    fn in_root(root: &Path) -> Result<Self> {
        // Establish cleanup ownership before creating a private workspace.
        let worker = worker()?;
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        // Resolve relative OS-temp overrides before changing the child's cwd;
        // neither canonicalize nor recreate the operator-selected root.
        let root = if root.is_absolute() {
            std::borrow::Cow::Borrowed(root)
        } else {
            std::borrow::Cow::Owned(std::path::absolute(root).map_err(WorkspaceAllocationError)?)
        };
        let path = root.join(format!(
            "agmi-model-{}-{timestamp}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        private_directory(&path)?;
        OUTSTANDING.fetch_add(1, Ordering::Relaxed);
        Ok(Self(path, worker))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        // Transfer the unique root; neither filesystem recursion nor a thread join
        // may run on a native collector or the Tokio runtime's teardown path.
        let _ = self.1.send(Cleanup::Remove(std::mem::take(&mut self.0)));
    }
}

#[cfg(test)]
pub(crate) async fn pause_native_cleanup_for_test() -> mpsc::Sender<()> {
    let (started, observed) = tokio::sync::oneshot::channel();
    let (release, receiver) = mpsc::channel();
    worker()
        .unwrap()
        .send(Cleanup::Pause(started, receiver))
        .unwrap();
    observed.await.unwrap();
    release
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_errors_preserve_sources_and_only_classify_allocation() {
        use contract::NativeReasonCode::*;
        for (errno, expected) in [
            (libc::ENOENT, NativeWorkspaceUnavailable),
            (libc::ENOTDIR, NativeWorkspaceUnavailable),
            (libc::ENOSPC, NativeWorkspaceCapacity),
            (libc::EDQUOT, NativeWorkspaceCapacity),
            (libc::EACCES, NativeWorkspacePermission),
            (libc::EPERM, NativeWorkspacePermission),
            (libc::EROFS, NativeWorkspacePermission),
            (libc::EIO, NativeWorkspaceFailure),
            (libc::EEXIST, NativeWorkspaceFailure),
        ] {
            let error = anyhow::Error::new(WorkspaceAllocationError(
                std::io::Error::from_raw_os_error(errno),
            ));
            assert_eq!(contract::NativeReasonCode::from_error(&error), expected);
            assert_eq!(failure_code(&error), expected.as_str());
            assert!(!execution_may_have_started(&error));
            assert_eq!(
                error
                    .chain()
                    .last()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(errno)
            );
            assert_eq!(
                serde_json::from_value::<contract::NativeReasonCode>(json!(expected.as_str()))
                    .unwrap(),
                expected
            );
            // The same OS error outside allocation (worker or SDK I/O) does
            // not prove a prelaunch workspace fault.
            let unrelated = anyhow::Error::new(std::io::Error::from_raw_os_error(errno));
            assert_eq!(
                contract::NativeReasonCode::from_error(&unrelated),
                NativeFailure
            );
            assert!(execution_may_have_started(&unrelated));
        }
    }

    #[test]
    fn missing_and_non_directory_roots_are_not_recreated_or_replaced() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let file = root.path().join("file");
        std::fs::write(&file, b"preserve").unwrap();
        for path in [&missing, &file] {
            let error = Scratch::in_root(path).err().unwrap();
            assert_eq!(
                contract::NativeReasonCode::from_error(&error),
                contract::NativeReasonCode::NativeWorkspaceUnavailable
            );
            assert!(!execution_may_have_started(&error));
        }
        assert!(!missing.exists());
        assert_eq!(std::fs::read(file).unwrap(), b"preserve");
    }

    #[tokio::test]
    async fn relative_temp_override_is_absolute_private_and_inherited_by_native_children() {
        const ISOLATED: &str = "AGMI_TEST_RELATIVE_TEMP_ROOT";
        if std::env::var_os(ISOLATED).is_none() {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir(root.path().join("relative")).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "solver::cleanup::tests::relative_temp_override_is_absolute_private_and_inherited_by_native_children",
                    "--nocapture",
                ])
                .current_dir(root.path())
                .env("TMPDIR", "relative")
                .env(ISOLATED, "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            return;
        }
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(std::env::temp_dir(), PathBuf::from("relative"));
        let scratch = Scratch::new().unwrap();
        let other = Scratch::new().unwrap();
        assert!(scratch.0.is_absolute());
        assert_eq!(scratch.0.parent().unwrap(), cwd.join("relative"));
        assert_ne!(scratch.0, other.0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&scratch.0).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        invoke(
            &std::env::current_exe().unwrap(),
            &[
                "--exact".into(),
                "solver::cleanup::tests::native_child_temp_probe".into(),
                "--ignored".into(),
                "--nocapture".into(),
            ],
            b"",
            &scratch.0,
            NativeProtocol::Hermes,
        )
        .await
        .unwrap();
        assert_eq!(std::env::current_dir().unwrap(), cwd);
    }

    // Run only through spawn_native above to probe its env_clear allowlist.
    #[test]
    #[ignore]
    fn native_child_temp_probe() {
        let cwd = std::env::current_dir().unwrap();
        assert!(cwd.is_absolute());
        assert_eq!(std::env::temp_dir(), cwd);
        assert!(std::env::var_os("HOME").is_some());
        assert!(std::env::var_os("AGMI_TEST_RELATIVE_TEMP_ROOT").is_none());
        let temporary = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(temporary.path().parent().unwrap(), cwd);
    }
}

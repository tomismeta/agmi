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

pub(super) struct Scratch(pub(super) PathBuf, &'static mpsc::Sender<Cleanup>);
impl Scratch {
    pub(super) fn new() -> Result<Self> {
        // Establish cleanup ownership before creating a private workspace.
        let worker = worker()?;
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
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

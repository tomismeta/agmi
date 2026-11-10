use crate::config::Config;
use crate::lifecycle::LifecycleError;
use crate::store::{EventCursorError, JournalEvent, Store};
use anyhow::Result;
use std::io::{self, Write};
use std::time::Duration;

fn failure(code: &'static str, message: &'static str) -> anyhow::Error {
    LifecycleError { code, message }.into()
}

fn journal_error(error: anyhow::Error) -> anyhow::Error {
    match error.downcast_ref::<EventCursorError>() {
        Some(EventCursorError::Replaced) => failure(
            "logs_journal_replaced",
            "The journal changed while following logs; the stream stopped without switching journals.",
        ),
        Some(EventCursorError::Regressed) => failure(
            "logs_cursor_regressed",
            "The journal moved behind the observed log cursor; the stream stopped without replaying events.",
        ),
        Some(EventCursorError::Gap) => failure(
            "logs_history_gap",
            "Retained journal history no longer covers this log cursor; the stream stopped without skipping events.",
        ),
        None => failure(
            "logs_unavailable",
            "The local journal could not be read safely; no state was changed.",
        ),
    }
}

#[derive(serde::Serialize)]
struct Envelope<'a> {
    schema: &'static str,
    ok: bool,
    r#type: &'static str,
    data: &'a JournalEvent,
}

fn write_event(output: &mut impl Write, event: &JournalEvent, json: bool) -> io::Result<()> {
    if json {
        serde_json::to_writer(
            &mut *output,
            &Envelope {
                schema: "agmi.cli.v1",
                ok: true,
                r#type: "log_event",
                data: event,
            },
        )
        .map_err(|error| {
            io::Error::new(error.io_error_kind().unwrap_or(io::ErrorKind::Other), error)
        })?;
        writeln!(output)
    } else if let Some(kind) = &event.kind {
        writeln!(
            output,
            "{} #{} {} {}",
            event.at, event.id, event.event, kind
        )
    } else {
        writeln!(output, "{} #{} {}", event.at, event.id, event.event)
    }
}

fn output_open(result: io::Result<()>) -> Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(_) => Err(failure(
            "logs_output_failed",
            "Log output could not be written; no state was changed.",
        )),
    }
}

struct Shutdown {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl Shutdown {
    fn new() -> Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                interrupt: signal(SignalKind::interrupt()).map_err(|_| signal_error())?,
                terminate: signal(SignalKind::terminate()).map_err(|_| signal_error())?,
            })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }

    async fn wait(&mut self) -> Result<()> {
        #[cfg(unix)]
        {
            let received = tokio::select! {
                received = self.interrupt.recv() => received,
                received = self.terminate.recv() => received,
            };
            received.ok_or_else(signal_error)
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await.map_err(|_| signal_error())
    }
}

fn signal_error() -> anyhow::Error {
    failure(
        "logs_signal_unavailable",
        "Log following could not receive shutdown signals; no state was changed.",
    )
}

/// Stream only the journal's public event projection. Configuration is borrowed
/// once; no credentials, runtime, guidance, or network clients are loaded here.
pub async fn follow(config: &Config, limit: usize, json: bool) -> Result<()> {
    let mut shutdown = Shutdown::new()?;
    let mut cursor = None;
    let mut caught_up = false;
    let stdout = io::stdout();
    loop {
        tokio::select! {
            biased;
            stopped = shutdown.wait() => return stopped,
            _ = async {
                if caught_up {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    tokio::task::yield_now().await;
                }
            } => {}
        }
        let page = Store::follow_events(config, cursor.as_ref(), limit).map_err(journal_error)?;
        for event in &page.events {
            tokio::select! {
                biased;
                stopped = shutdown.wait() => return stopped,
                _ = tokio::task::yield_now() => {}
            }
            let mut output = stdout.lock();
            if !output_open(write_event(&mut output, event, json))? || !output_open(output.flush())?
            {
                return Ok(());
            }
        }
        caught_up = !page.more;
        cursor = Some(page.cursor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> JournalEvent {
        JournalEvent {
            id: 42,
            at: 100,
            event: "model_result_captured".into(),
            kind: Some("answer".into()),
        }
    }

    #[test]
    fn broken_output_is_graceful_in_both_formats() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        for json in [false, true] {
            assert!(!output_open(write_event(&mut Closed, &event(), json)).unwrap());
        }
        assert!(!output_open(Closed.flush()).unwrap());
    }

    #[test]
    fn errors_never_expose_underlying_journal_or_output_details() {
        let error = journal_error(anyhow::anyhow!("private-path-and-payload-canary"));
        let error = error.downcast_ref::<LifecycleError>().unwrap();
        assert_eq!(error.code, "logs_unavailable");
        assert!(!error.message.contains("canary"));
        let error = output_open(Err(io::Error::other("private-output-canary"))).unwrap_err();
        let error = error.downcast_ref::<LifecycleError>().unwrap();
        assert_eq!(error.code, "logs_output_failed");
        assert!(!error.message.contains("canary"));
    }
}
